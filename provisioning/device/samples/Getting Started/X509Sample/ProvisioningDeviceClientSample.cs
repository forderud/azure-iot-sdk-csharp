// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Azure.Devices.Client;
using Microsoft.Azure.Devices.Provisioning.Client.Transport;
using Microsoft.Azure.Devices.Shared;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Azure.Devices.Provisioning.Client.Samples
{
    /// <summary>
    /// Demonstrates how to register a device with the device provisioning service using a certificate, and then
    /// use the registration information to authenticate to IoT Hub.
    /// </summary>
    internal class ProvisioningDeviceClientSample
    {
        string m_IdScope;
        string m_CertificateName;
        string m_GlobalDeviceEndpoint;


        public ProvisioningDeviceClientSample(string IdScope, string CertificateName, string GlobalDeviceEndpoint)
        {
            m_IdScope = IdScope;
            m_CertificateName = CertificateName;
            m_GlobalDeviceEndpoint = GlobalDeviceEndpoint;

        }

        public async Task RunSampleAsync()
        {
            Console.WriteLine($"Loading the certificate...");
            using X509Certificate2 certificate = GetClientCertificate(m_CertificateName);
            using var security = new SecurityProviderX509Certificate(certificate);

            Console.WriteLine($"Initializing the device provisioning client...");

            using ProvisioningTransportHandler transport = new ProvisioningTransportHandlerMqtt();
            var provClient = ProvisioningDeviceClient.Create(
                m_GlobalDeviceEndpoint,
                m_IdScope,
                security,
                transport);

            Console.WriteLine($"Initialized for registration Id {security.GetRegistrationID()}.");

            Console.WriteLine("Registering with the device provisioning service... ");
            DeviceRegistrationResult result = await provClient.RegisterAsync();

            Console.WriteLine($"Registration status: {result.Status}.");
            if (result.Status != ProvisioningRegistrationStatusType.Assigned)
            {
                Console.WriteLine($"Registration status did not assign a hub, so exiting this sample.");
                return;
            }

            Console.WriteLine($"Device {result.DeviceId} registered to {result.AssignedHub}.");

            Console.WriteLine("Creating X509 authentication for IoT Hub...");
            using var auth = new DeviceAuthenticationWithX509Certificate(
                result.DeviceId,
                certificate);

            Console.WriteLine($"Testing the provisioned device with IoT Hub...");
            using var iotClient = DeviceClient.Create(result.AssignedHub, auth, TransportType.Mqtt);

            Console.WriteLine("Sending a telemetry message...");
            using var message = new Message(Encoding.UTF8.GetBytes("TestMessage"));
            await iotClient.SendEventAsync(message);

            await iotClient.CloseAsync();
            Console.WriteLine("Finished.");
        }

        static X509Certificate2 GetClientCertificate(string name)
        {
            // open personal certificate store
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.Subject.Substring(3) != name) // exclude "CN=" prefix from name check
                        continue;

                    if (!cert.HasPrivateKey)
                        continue;

                    return cert; // return matching certificate
                }
            }

            throw new ApplicationException("Certificate not found");
        }
    }
}
