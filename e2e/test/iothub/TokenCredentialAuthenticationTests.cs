﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Azure.Devices.Client;
using Microsoft.Azure.Devices.Common.Exceptions;
using Microsoft.Azure.Devices.E2ETests.Helpers;
using Microsoft.Azure.Devices.Shared;
using Microsoft.VisualStudio.TestTools.UnitTesting;

#if !NET451

using Microsoft.Rest;
using Azure.Core;
using Azure.Identity;

#endif

using ClientOptions = Microsoft.Azure.Devices.Client.ClientOptions;

namespace Microsoft.Azure.Devices.E2ETests.IotHub.Service
{
    /// <summary>
    /// Tests to ensure authentication using Azure active directory succeeds in all the clients.
    /// </summary>
    [TestClass]
    [TestCategory("E2E")]
    [TestCategory("IoTHub")]
    public class TokenCredentialAuthenticationTests : E2EMsTestBase
    {
        private readonly string _devicePrefix = $"{nameof(TokenCredentialAuthenticationTests)}_";

#if !NET451

        [LoggedTestMethod]
        [Timeout(TestTimeoutMilliseconds)]
        public async Task RegistryManager_Http_TokenCredentialAuth_Success()
        {
            // arrange
            using var registryManager = RegistryManager.Create(
                TestConfiguration.IotHub.GetIotHubHostName(),
                TestConfiguration.IotHub.GetClientSecretCredential());

            var device = new Device(Guid.NewGuid().ToString());

            // act
            Device createdDevice = await registryManager.AddDeviceAsync(device).ConfigureAwait(false);

            // assert
            Assert.IsNotNull(createdDevice);

            // cleanup
            await registryManager.RemoveDeviceAsync(device.Id).ConfigureAwait(false);
        }

        [LoggedTestMethod]
        [Timeout(TestTimeoutMilliseconds)]
        public async Task JobClient_Http_TokenCredentialAuth_Success()
        {
            // arrange
            using var jobClient = JobClient.Create(
                TestConfiguration.IotHub.GetIotHubHostName(),
                TestConfiguration.IotHub.GetClientSecretCredential());

            string jobId = "JOBSAMPLE" + Guid.NewGuid().ToString();
            string jobDeviceId = "JobsSample_Device";
            string query = $"DeviceId IN ['{jobDeviceId}']";
            var twin = new Twin(jobDeviceId);

            try
            {
                // act
                JobResponse createJobResponse = await jobClient
                    .ScheduleTwinUpdateAsync(
                        jobId,
                        query,
                        twin,
                        DateTime.UtcNow,
                        (long)TimeSpan.FromMinutes(2).TotalSeconds)
                    .ConfigureAwait(false);
            }
            catch (ThrottlingException)
            {
                // Concurrent jobs can be rejected, but it still means authentication was successful. Ignore the exception.
            }
        }

        [LoggedTestMethod]
        [Timeout(TestTimeoutMilliseconds)]
        public async Task DigitalTwinClient_Http_TokenCredentialAuth_Success()
        {
            // arrange
            TestDevice testDevice = await TestDevice.GetTestDeviceAsync(Logger, _devicePrefix).ConfigureAwait(false);
            string thermostatModelId = "dtmi:com:example:TemperatureController;1";

            // Create a device client instance initializing it with the "Thermostat" model.
            var options = new ClientOptions
            {
                ModelId = thermostatModelId,
            };
            using DeviceClient deviceClient = testDevice.CreateDeviceClient(Client.TransportType.Mqtt, options);

            // Call openAsync() to open the device's connection, so that the ModelId is sent over Mqtt CONNECT packet.
            await deviceClient.OpenAsync().ConfigureAwait(false);

            using var digitalTwinClient = DigitalTwinClient.Create(
                TestConfiguration.IotHub.GetIotHubHostName(),
                TestConfiguration.IotHub.GetClientSecretCredential());

            // act
            HttpOperationResponse<ThermostatTwin, DigitalTwinGetHeaders> response = await digitalTwinClient
                .GetDigitalTwinAsync<ThermostatTwin>(testDevice.Id)
                .ConfigureAwait(false);
            ThermostatTwin twin = response.Body;

            // assert
            twin.Metadata.ModelId.Should().Be(thermostatModelId);

            // cleanup
            await testDevice.RemoveDeviceAsync().ConfigureAwait(false);
        }

        [LoggedTestMethod]
        [Timeout(TestTimeoutMilliseconds)]
        public async Task Service_Amqp_TokenCredentialAuth_Success()
        {
            // arrange
            string ghostDevice = $"{nameof(Service_Amqp_TokenCredentialAuth_Success)}_{Guid.NewGuid()}";
            using var serviceClient = ServiceClient.Create(
                TestConfiguration.IotHub.GetIotHubHostName(),
                TestConfiguration.IotHub.GetClientSecretCredential(),
                TransportType.Amqp);
            await serviceClient.OpenAsync().ConfigureAwait(false);
            using var message = new Message(Encoding.ASCII.GetBytes("Hello, Cloud!"));

            // act
            Func<Task> act = async () => await serviceClient.SendAsync(ghostDevice, message).ConfigureAwait(false);

            // assert
            await act.Should().ThrowAsync<DeviceNotFoundException>();
        }

#endif
    }
}
