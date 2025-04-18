/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce.rocketMQ;

import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugins.detectors.rce.rocketMQ.RCEInRocketMQWithOpenAccessDetector;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO: add test without callback server

/** Unit tests for {@link RCEInRocketMQWithOpenAccessDetector}. */
@RunWith(JUnit4.class)
public final class RCEInRocketMQWithOpenAccessDetectorWithCallbackServerTest {

    private final FakeUtcClock fakeUtcClock = FakeUtcClock.create()
        .setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

    @Inject
    private RCEInRocketMQWithOpenAccessDetector detector;

    private MockWebServer mockRocketMQService;
    private MockWebServer mockCallbackServer;

    public RCEInRocketMQWithOpenAccessDetectorWithCallbackServerTest() {}

    @Before
    public void setUp() throws IOException {
        mockRocketMQService = new MockWebServer();
        mockCallbackServer = new MockWebServer();
        mockRocketMQService.start();
        mockCallbackServer.start();

        Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .build(),
            new RCEInRocketMQWithOpenAccessBootstrapModule()
        ).injectMembers(this);
    }

    @After
    public void tearDown() throws Exception {
        mockCallbackServer.shutdown();
        mockRocketMQService.shutdown();
    }

    @Test
    public void detect_whenVulnerable_reportsVulnerability() {}

    @Test
    public void detect_whenNotVulnerable_doesNotReportVulnerability() {}
}
