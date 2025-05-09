using System;
using DotMake.CommandLine;
using Microsoft.Data.SqlClient;
using System.Data;
using System.Net.Http;
using System.Threading.Tasks;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.WebSockets;
using DotNetEnv;

DotNetEnv.Env.TraversePath().Load();

//AlwaysEncrypted.InitData();

//AlwaysEncrypted.ReadWithoutKeys();

//AlwaysEncrypted.ReadWithKeys();

//Vault.InitData();

//Vault.ReadData(decrypt: false);

//Vault.ReadData(decrypt: true);


Console.WriteLine("Complete");


public static class AlwaysEncrypted {
    public static void InitData() {
        string cstr = Environment.GetEnvironmentVariable("AE_CONNECTION");
        using (SqlConnection conn = new SqlConnection(cstr)) {
            conn.Open();
            var writeconn = new SqlConnection(cstr);
            writeconn.Open();
            var qcmd = new SqlCommand("SELECT au_id, phone FROM authors",conn);
            using (SqlDataReader reader = qcmd.ExecuteReader()) {
                while (reader.Read()) {
                    var ucmd = new SqlCommand();
                    ucmd.Connection = writeconn;
                    ucmd.CommandText = "UpdateExtData";
                    ucmd.CommandType = CommandType.StoredProcedure;
                    SqlParameter id = new SqlParameter("@id", SqlDbType.VarChar, 11);
                    id.Value = reader[0];
                    SqlParameter ssn = new SqlParameter("@ssn", SqlDbType.NVarChar, 11);
                    ssn.Value = reader[0];
                    SqlParameter phone = new SqlParameter("@phone", SqlDbType.NVarChar, 12);
                    phone.Value = reader[1];
                    ucmd.Parameters.Add(id);
                    ucmd.Parameters.Add(ssn);
                    ucmd.Parameters.Add(phone);
                    var res = ucmd.ExecuteNonQuery();
                    Console.WriteLine($@"{reader[0]} - {reader[1]}");
                }
            }
        }
    }

    public static void ReadWithoutKeys() {
        string cstr = Environment.GetEnvironmentVariable("NON_AE_CONNECTION");
        using (SqlConnection conn = new SqlConnection(cstr)) {
            conn.Open();
            using(SqlCommand cmd = new SqlCommand()) {
                cmd.CommandText = "SELECT au_id, ae_ssn, ae_bat_phone FROM authors";
                cmd.CommandType = CommandType.Text;
                cmd.Connection = conn;
                using(SqlDataReader rdr = cmd.ExecuteReader()) {
                    while(rdr.Read()) {
                        Console.WriteLine(@"{0} - {1} / {2}", rdr[0],  BitConverter.ToString((byte[])rdr[1]).Substring(0,20), BitConverter.ToString((byte[])rdr[2]).Substring(0,20) );
                    }
                }

            } 
        }
    }
    public static void ReadWithKeys() {
        string cstr = Environment.GetEnvironmentVariable("AE_CONNECTION");
        using (SqlConnection conn = new SqlConnection(cstr)) {
            conn.Open();
            using(SqlCommand cmd = new SqlCommand()) {
                cmd.CommandText = "SELECT au_id, ae_ssn, ae_bat_phone FROM authors";
                cmd.CommandType = CommandType.Text;
                cmd.Connection = conn;
                using(SqlDataReader rdr = cmd.ExecuteReader()) {
                    while(rdr.Read()) {
                        Console.WriteLine(@"{0} - {1} / {2}", rdr[0],  rdr[1], rdr[2] );
                    }
                }

            } 
        }
    }
}

public static class Vault { 
    public static void InitData() {
        string cstr = Environment.GetEnvironmentVariable("NON_AE_CONNECTION");
        using (SqlConnection conn = new SqlConnection(cstr)) {
            conn.Open();
            var writeconn = new SqlConnection(cstr);
            writeconn.Open();
            var qcmd = new SqlCommand("SELECT au_id, phone FROM authors",conn);
            using (SqlDataReader reader = qcmd.ExecuteReader()) {
                while (reader.Read()) {
                    var ucmd = new SqlCommand();
                    ucmd.Connection = writeconn;
                    ucmd.CommandText = "UPDATE authors SET ext_ssn = @ssn, ext_bat_phone = @phone WHERE au_id = @id";
                    ucmd.CommandType = CommandType.Text;
                    SqlParameter id = new SqlParameter("@id", SqlDbType.VarChar, 11);
                    id.Value = reader[0];
                    SqlParameter ssn = new SqlParameter("@ssn", SqlDbType.NVarChar);
                    ssn.Value = VaultUtil.EncryptWithAcctKey(reader[0].ToString());
                    SqlParameter phone = new SqlParameter("@phone", SqlDbType.NVarChar);
                    phone.Value = VaultUtil.EncryptWithSalesKey(reader[1].ToString());
                    ucmd.Parameters.Add(id);
                    ucmd.Parameters.Add(ssn);
                    ucmd.Parameters.Add(phone);
                    var res = ucmd.ExecuteNonQuery();
                    Console.WriteLine($@"{reader[0]} - {reader[1]}");
                }
            }
        }
    }
    public static void ReadData(bool decrypt) {
        string cstr = Environment.GetEnvironmentVariable("NON_AE_CONNECTION");
        using (SqlConnection conn = new SqlConnection(cstr)) {
            conn.Open();
            using(SqlCommand cmd = new SqlCommand()) {
                cmd.CommandText = "SELECT au_id, ext_ssn, ext_bat_phone FROM authors";
                cmd.CommandType = CommandType.Text;
                cmd.Connection = conn;
                using(SqlDataReader rdr = cmd.ExecuteReader()) {
                    while(rdr.Read()) {
                        if(decrypt) {
                            Console.WriteLine(@"{0} - {1} / {2}", rdr[0],  VaultUtil.DecryptWithAcctKey(rdr[1].ToString()), VaultUtil.DecryptWithSalesKey(rdr[2].ToString()) );
                        } else {
                            Console.WriteLine(@"{0} - {1} / {2}", rdr[0],  rdr[1], rdr[2] );
                        }
                    }
                }
            } 
        }
    }

}

public static class VaultUtil{

    private static string encrypt(string value, string key) {
        using (var client = new HttpClient()) {
            string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
            client.DefaultRequestHeaders.Add("X-Vault-Token", Environment.GetEnvironmentVariable("VAULT_TOKEN"));
            client.DefaultRequestHeaders.Add("X-Vault-Namespace", Environment.GetEnvironmentVariable("VAULT_NAMESPACE"));
            var message = client.PostAsync("http://localhost:8200/v1/transit/encrypt/" + key, new StringContent("{\"plaintext\": \"" + payload + "\"}")).GetAwaiter().GetResult();
            var content = message.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return (string)JsonObject.Parse(content)["data"]["ciphertext"];
        }
    }

    private static string decrypt(string value, string key) {
        using (var client = new HttpClient()) {
            client.DefaultRequestHeaders.Add("X-Vault-Token", Environment.GetEnvironmentVariable("VAULT_TOKEN"));
            client.DefaultRequestHeaders.Add("X-Vault-Namespace", Environment.GetEnvironmentVariable("VAULT_NAMESPACE"));
            var message = client.PostAsync("http://localhost:8200/v1/transit/decrypt/" + key, new StringContent("{\"ciphertext\": \"" + value + "\"}")).GetAwaiter().GetResult();
            var content = message.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var work = (string)JsonObject.Parse(content)["data"]["plaintext"];
            return Encoding.UTF8.GetString(Convert.FromBase64String(work));
        }
    }
    public static string EncryptWithAcctKey(string value) {
        return encrypt(value, "acct");
    }
    public static string DecryptWithAcctKey(string value) {
        return decrypt(value, "acct");
    }
    public static string EncryptWithSalesKey(string value) {
        return encrypt(value, "sales");
    }
    public static string DecryptWithSalesKey(string value) {
        return decrypt(value, "sales");
    }
}