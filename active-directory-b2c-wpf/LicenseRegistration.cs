using System;
using System.Text.Json.Serialization;

namespace active_directory_b2c_wpf
{
    public class LicenseRegistration
    {
        [JsonPropertyName("vid")]
        public string VendorId { get; set; }
        
        [JsonPropertyName("iid")]
        public string InstallId { get; set; }
        
        [JsonPropertyName("cid")]
        public string CryptographicId { get; set; }
        
        [JsonPropertyName("aid")]
        public string AdvertisingId { get; set; } = string.Empty;
        
        [JsonPropertyName("oid")]
        public string ObjectId { get; set; }
    }
}