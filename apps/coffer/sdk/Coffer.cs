// Coffer client in one file, using only the .NET base class library (.NET 8+).
// Secrets are encrypted and decrypted here; the Coffer server only ever sees ciphertext.
//
//   COFFER_URL=__COFFER_URL__        (optional; defaults to the URL below)
//   COFFER_CLIENT_ID=cfi_...
//   COFFER_CLIENT_SECRET=cfs_...
//
//   using var coffer = CofferSdk.Coffer.FromEnv();
//   var all = await coffer.ListAllSecretsAsync();                // Dictionary<string, string>
//   string? db = await coffer.GetSecretAsync("DATABASE_URL");    // null if missing
//   int version = await coffer.WriteSecretAsync("API_TOKEN", "s3cr3t");  // needs a read-write client ID
//   bool deleted = await coffer.DeleteSecretAsync("API_TOKEN");
//
// Protocol (Coffer v1). HKDF is HKDF-SHA256 with a 32-byte zero salt and 32-byte output.
//   authKey  = HKDF(utf8(clientSecret), "coffer/v1/machine-auth")   sent as "Bearer <clientId>.<base64 authKey>"
//   wrapKey  = HKDF(utf8(clientSecret), "coffer/v1/machine-wrap")
//   envKey   = AES-256-GCM-open(wrapKey, identity.wrappedKey, aad "coffer/v1/machine-key/<clientId>")
//   encKey   = HKDF(envKey, "coffer/v1/secret-enc");  indexKey = HKDF(envKey, "coffer/v1/secret-index")
//   mac      = hex(HMAC-SHA256(indexKey, utf8(name)))
//   secret   = AES-256-GCM(encKey, utf8(JSON {"name","value"}), aad "coffer/v1/secret/<envId>/<mac>")
//   {iv, ct} are base64; ct is ciphertext followed by the 16-byte tag.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace CofferSdk;

public sealed class CofferException(int status, string code, string message) : Exception($"Coffer: {message} ({status})")
{
	public int Status { get; } = status;
	public string Code { get; } = code;
}

public sealed record CofferIdentity(string ClientId, string Scope, string ProjectId, string Project, string EnvId, string Environment);

public sealed class Coffer : IDisposable
{
	private const string DefaultUrl = "__COFFER_URL__";
	private const int TagSize = 16;
	private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

	private sealed record Sealed(string Iv, string Ct);
	private sealed record SecretRow(string Mac, string Iv, string Ct, int Version);
	private sealed record SecretList(List<SecretRow> Secrets);
	private sealed record Deleted(bool deleted);
	private sealed record IdentityResponse(string ClientId, string Scope, string ProjectId, string Project, string EnvId, string Environment, Sealed WrappedKey);
	private sealed record Plain(string name, string value);
	private sealed record ErrorBody(string? Error, string? Message);
	private sealed class Keys(IdentityResponse identity, byte[] enc, byte[] index)
	{
		public IdentityResponse Identity { get; } = identity;
		public byte[] Enc { get; } = enc;
		public byte[] Index { get; } = index;
	}

	private readonly string _url;
	private readonly string _clientId;
	private readonly string _clientSecret;
	private readonly string _auth;
	private readonly HttpClient _http;
	private readonly bool _ownsHttp;
	private readonly SemaphoreSlim _lock = new(1, 1);
	private Keys? _keys;

	public Coffer(string url, string clientId, string clientSecret, HttpClient? http = null)
	{
		if (!Regex.IsMatch(clientId, "^cfi_[A-Za-z0-9_-]{22}$")) throw new ArgumentException("Coffer: invalid client ID", nameof(clientId));
		if (!clientSecret.StartsWith("cfs_", StringComparison.Ordinal)) throw new ArgumentException("Coffer: invalid client secret", nameof(clientSecret));
		_url = url.TrimEnd('/');
		_clientId = clientId;
		_clientSecret = clientSecret;
		_auth = $"{clientId}.{Convert.ToBase64String(Derive(Encoding.UTF8.GetBytes(clientSecret), "coffer/v1/machine-auth"))}";
		_ownsHttp = http is null;
		_http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
	}

	/// <summary>Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET and optionally COFFER_URL.</summary>
	public static Coffer FromEnv()
	{
		var id = Environment.GetEnvironmentVariable("COFFER_CLIENT_ID");
		var secret = Environment.GetEnvironmentVariable("COFFER_CLIENT_SECRET");
		if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(secret)) throw new InvalidOperationException("Coffer: set COFFER_CLIENT_ID and COFFER_CLIENT_SECRET");
		var url = Environment.GetEnvironmentVariable("COFFER_URL");
		return new Coffer(string.IsNullOrEmpty(url) ? DefaultUrl : url, id, secret);
	}

	/// <summary>All secrets of this client's environment, by name.</summary>
	public async Task<Dictionary<string, string>> ListAllSecretsAsync(CancellationToken ct = default)
	{
		var k = await LoadAsync(ct).ConfigureAwait(false);
		var list = await RequestAsync<SecretList>(HttpMethod.Get, "/secrets", null, ct).ConfigureAwait(false);
		var result = new Dictionary<string, string>(StringComparer.Ordinal);
		foreach (var row in list.Secrets)
		{
			var p = Decrypt(k, row);
			result[p.name] = p.value;
		}
		return result;
	}

	/// <summary>One secret's value, or null if it does not exist.</summary>
	public async Task<string?> GetSecretAsync(string name, CancellationToken ct = default)
	{
		var k = await LoadAsync(ct).ConfigureAwait(false);
		try
		{
			return Decrypt(k, await RequestAsync<SecretRow>(HttpMethod.Get, $"/secrets/{Mac(k, name)}", null, ct).ConfigureAwait(false)).value;
		}
		catch (CofferException e) when (e.Status == (int)HttpStatusCode.NotFound)
		{
			return null;
		}
	}

	/// <summary>Create or replace a secret. Returns its new version number.</summary>
	public async Task<int> WriteSecretAsync(string name, string value, CancellationToken ct = default)
	{
		if (string.IsNullOrEmpty(name)) throw new ArgumentException("Coffer: empty secret name", nameof(name));
		var k = await LoadAsync(ct).ConfigureAwait(false);
		var mac = Mac(k, name);
		var sealedSecret = Seal(k.Enc, JsonSerializer.SerializeToUtf8Bytes(new Plain(name, value)), $"coffer/v1/secret/{k.Identity.EnvId}/{mac}");
		var row = await RequestAsync<SecretRow>(HttpMethod.Put, $"/secrets/{mac}", sealedSecret, ct).ConfigureAwait(false);
		return row.Version;
	}

	/// <summary>Returns false if the secret did not exist.</summary>
	public async Task<bool> DeleteSecretAsync(string name, CancellationToken ct = default)
	{
		var k = await LoadAsync(ct).ConfigureAwait(false);
		return (await RequestAsync<Deleted>(HttpMethod.Delete, $"/secrets/{Mac(k, name)}", null, ct).ConfigureAwait(false)).deleted;
	}

	/// <summary>Project, environment and scope of this client ID.</summary>
	public async Task<CofferIdentity> IdentityAsync(CancellationToken ct = default)
	{
		var i = (await LoadAsync(ct).ConfigureAwait(false)).Identity;
		return new CofferIdentity(i.ClientId, i.Scope, i.ProjectId, i.Project, i.EnvId, i.Environment);
	}

	public void Dispose()
	{
		if (_ownsHttp) _http.Dispose();
		_lock.Dispose();
	}

	private static byte[] Derive(byte[] ikm, string info) =>
		HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, new byte[32], Encoding.UTF8.GetBytes(info));

	private static string Mac(Keys k, string name) =>
		Convert.ToHexString(HMACSHA256.HashData(k.Index, Encoding.UTF8.GetBytes(name))).ToLowerInvariant();

	private static byte[] Open(byte[] key, string iv, string ct, string aad)
	{
		var nonce = Convert.FromBase64String(iv);
		var data = Convert.FromBase64String(ct);
		if (data.Length < TagSize) throw new CryptographicException("Coffer: ciphertext too short");
		var plain = new byte[data.Length - TagSize];
		using var aes = new AesGcm(key, TagSize);
		aes.Decrypt(nonce, data.AsSpan(0, plain.Length), data.AsSpan(plain.Length), plain, Encoding.UTF8.GetBytes(aad));
		return plain;
	}

	private static Sealed Seal(byte[] key, byte[] plain, string aad)
	{
		var nonce = RandomNumberGenerator.GetBytes(12);
		var data = new byte[plain.Length + TagSize];
		using var aes = new AesGcm(key, TagSize);
		aes.Encrypt(nonce, plain, data.AsSpan(0, plain.Length), data.AsSpan(plain.Length), Encoding.UTF8.GetBytes(aad));
		return new Sealed(Convert.ToBase64String(nonce), Convert.ToBase64String(data));
	}

	private static Plain Decrypt(Keys k, SecretRow row)
	{
		var bytes = Open(k.Enc, row.Iv, row.Ct, $"coffer/v1/secret/{k.Identity.EnvId}/{row.Mac}");
		var p = JsonSerializer.Deserialize<Plain>(bytes, Json) ?? throw new CryptographicException("Coffer: empty secret");
		if (Mac(k, p.name) != row.Mac) throw new CryptographicException("Coffer: secret name does not match its index");
		return p;
	}

	private async Task<Keys> LoadAsync(CancellationToken ct)
	{
		if (_keys is not null) return _keys;
		await _lock.WaitAsync(ct).ConfigureAwait(false);
		try
		{
			if (_keys is not null) return _keys;
			var id = await RequestAsync<IdentityResponse>(HttpMethod.Get, "/identity", null, ct).ConfigureAwait(false);
			var wrap = Derive(Encoding.UTF8.GetBytes(_clientSecret), "coffer/v1/machine-wrap");
			var envKey = Open(wrap, id.WrappedKey.Iv, id.WrappedKey.Ct, $"coffer/v1/machine-key/{_clientId}");
			_keys = new Keys(id, Derive(envKey, "coffer/v1/secret-enc"), Derive(envKey, "coffer/v1/secret-index"));
			CryptographicOperations.ZeroMemory(envKey);
			CryptographicOperations.ZeroMemory(wrap);
			return _keys;
		}
		finally
		{
			_lock.Release();
		}
	}

	private async Task<T> RequestAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
	{
		using var req = new HttpRequestMessage(method, $"{_url}/api/v1{path}");
		req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _auth);
		if (body is not null)
		{
			req.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(body, Json));
			req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
		}
		using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
		var bytes = await res.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
		if (!res.IsSuccessStatusCode)
		{
			ErrorBody? e = null;
			try { e = JsonSerializer.Deserialize<ErrorBody>(bytes, Json); } catch (JsonException) { }
			throw new CofferException((int)res.StatusCode, e?.Error ?? "http_error", e?.Message ?? e?.Error ?? res.ReasonPhrase ?? "request failed");
		}
		return JsonSerializer.Deserialize<T>(bytes, Json) ?? throw new CofferException((int)res.StatusCode, "empty_response", "empty response");
	}
}
