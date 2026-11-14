// Test runner for Coffer.cs; see scripts/sdk-matrix.ts.
using System.Text.Json;
using CofferSdk;

var lang = args[0];
using var c = Coffer.FromEnv();
var version = await c.WriteSecretAsync($"FROM_{lang}", $"hello from {lang} ünï ✓ \"q\"\n<&>");
var got = await c.GetSecretAsync($"FROM_{lang}");
var missing = await c.GetSecretAsync("NOPE_MISSING");
await c.WriteSecretAsync($"TMP_{lang}", "x");
var d1 = await c.DeleteSecretAsync($"TMP_{lang}");
var d2 = await c.DeleteSecretAsync($"TMP_{lang}");
var all = await c.ListAllSecretsAsync();
Console.WriteLine(JsonSerializer.Serialize(new { version, got, missingFound = missing is not null, deletedOnce = d1, deletedTwice = d2, all }));
