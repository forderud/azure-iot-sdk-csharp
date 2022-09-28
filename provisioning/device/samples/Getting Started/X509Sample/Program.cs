﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;
using System;
using System.Threading.Tasks;

namespace Microsoft.Azure.Devices.Provisioning.Client.Samples
{
    /// <summary>
    /// A sample to illustrate connecting a device to hub using the device provisioning service and a certificate.
    /// </summary>
    internal class Program
    {
        public static async Task<int> Main(string[] args)
        {

            if (args.Length < 2)
            {
                Console.Error.WriteLine("ERROR: IdScope and CertificateName arguments missing.");
                return -1;
            }

            string IdScope = args[0];
            string CertificateName = args[1];
            string GlobalDeviceEndpoint = "global.azure-devices-provisioning.net";

            var sample = new ProvisioningDeviceClientSample(IdScope, CertificateName, GlobalDeviceEndpoint);
            await sample.RunSampleAsync();

            return 0;
        }
    }
}
