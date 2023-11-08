﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Text;
using System.Windows;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Desktop;

namespace active_directory_b2c_wpf
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        /// <summary>
        /// B2C tenant name
        /// </summary>
        private static readonly string TenantName = "aaomb2cadt";
        private static readonly string Tenant = $"{TenantName}.onmicrosoft.com";
        private static readonly string AzureAdB2CHostname = $"{TenantName}.b2clogin.com";

        /// <summary>
        /// ClientId for the application which initiates the login functionality (this app)  
        /// </summary>
        private static readonly string ClientId = "721364af-3bbb-4889-94ab-49c447f0b9b4";

        /// <summary>
        /// Should be one of the choices on the Azure AD B2c / [This App] / Authentication blade
        /// </summary>
        private static readonly string RedirectUri = $"https://{TenantName}.b2clogin.com/oauth2/nativeclient";

        /// <summary>
        /// From Azure AD B2C / UserFlows blade
        /// </summary>
        public static string PolicySignUpSignIn = "B2C_1_Licenses_SignUpSignIn";
        public static string PolicyEditProfile = "B2C_1_Licenses_EditProfile";
        public static string PolicyResetPassword = "B2C_1_Licenses_PasswordReset";

        /// <summary>
        /// Note: AcquireTokenInteractive will fail to get the AccessToken if "Admin Consent" has not been granted to this scope.  To achieve this:
        /// 
        /// 1st: Azure AD B2C / App registrations / [API App] / Expose an API / Add a scope
        /// 2nd: Azure AD B2C / App registrations / [This App] / API Permissions / Add a permission / My APIs / [API App] / Select & Add Permissions
        /// 3rd: Azure AD B2C / App registrations / [This App] / API Permissions / ... (next to add a permission) / Grant Admin Consent for [tenant]
        /// </summary>
        public static string[] ApiScopes = { $"https://{Tenant}/license-api/Licenses.Read" };

        /// <summary>
        /// URL for API which will receive the bearer token corresponding to this authentication
        /// </summary>
        public static string QueryLicensesApiEndpoint = "https://licenses.acmeaom.com/v1/licenses";

        /// <summary>
        /// URL for API which uses claims from the token after authentication. The endpoint is for
        /// apple, because that is the one that is available right now, but the pattern is the same
        /// for other platforms.
        /// </summary>
        public static string RegisterLicensesApiEndpoint = "https://installs.acmeaom.com/microsoft/v1/installs";
        
        // This key is for the example only and will be deleted once the system is in production.
        public static string RegisterLicensesKey = "DGx29PyU8iCwxTNCHmVw9s16oWtoO8yTN6Scsm7RXbg0AzFuEO94Vw==";


        
        // Shouldn't need to change these:
        private static string AuthorityBase = $"https://{AzureAdB2CHostname}/tfp/{Tenant}/";
        public static string AuthoritySignUpSignIn = $"{AuthorityBase}{PolicySignUpSignIn}";
        public static string AuthorityEditProfile = $"{AuthorityBase}{PolicyEditProfile}";
        public static string AuthorityResetPassword = $"{AuthorityBase}{PolicyResetPassword}";

        public static IPublicClientApplication PublicClientApp { get; private set; }

        static App()
        {
            PublicClientApp = PublicClientApplicationBuilder.Create(ClientId)
                .WithB2CAuthority(AuthoritySignUpSignIn)
                .WithRedirectUri(RedirectUri)
                .WithWindowsEmbeddedBrowserSupport()
                .WithLogging(Log, LogLevel.Info, true) 
                .Build();

            TokenCacheHelper.Bind(PublicClientApp.UserTokenCache);
        }

        private static void Log(LogLevel level, string message, bool containsPii)
        {
            string logs = $"{level} {message}{Environment.NewLine}";
            File.AppendAllText(System.Reflection.Assembly.GetExecutingAssembly().Location + ".msalLogs.txt", logs);
        }
    }
}