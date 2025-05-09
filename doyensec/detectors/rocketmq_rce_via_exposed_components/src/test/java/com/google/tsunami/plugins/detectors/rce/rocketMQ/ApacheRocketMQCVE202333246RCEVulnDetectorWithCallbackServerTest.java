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

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Key;
import com.google.inject.multibindings.OptionalBinder;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.rce.rocketMQ.ApacheRocketMQCVE202333246RCEVulnDetector.SocketFactoryInstance;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import javax.net.SocketFactory;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ApacheRocketMQCVE202333246RCEVulnDetector}. */
@RunWith(JUnit4.class)
public final class ApacheRocketMQCVE202333246RCEVulnDetectorWithCallbackServerTest {

  @Inject private ApacheRocketMQCVE202333246RCEVulnDetector detector;
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };
  private final MockWebServer mockCallbackServer = new MockWebServer();

  final String serverInfoResponse =
      "\u0000\u0000\u0000\u00f5\u0000\u0000\u0000\u00f1\u0000{\"code\":1,\"flag\":1,\"language\":\"JAVA\",\"opaque\":0,\"remark\":\"java.lang.NullPointerException,"
          + " org.apache.rocketmq.broker.processor.QueryMessageProcessor.queryMessage(QueryMessageProcessor.java:87)\",\"serializeTypeCurrentRPC\":\"JSON\",\"version\":433}";

  @Before
  public void setUp() throws IOException {
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(
                        binder(), Key.get(SocketFactory.class, SocketFactoryInstance.class))
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            Modules.override(new ApacheRocketMQCVE202333246RCEVulnDetectorBootstrapModule())
                .with(BoundFieldModule.of(this)),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  public void setUpNoOob() throws IOException {
    mockCallbackServer.shutdown();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new ApacheRocketMQCVE202333246RCEVulnDetectorBootstrapModule(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(null)
                .setSecureRng(testSecureRandom)
                .build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(
                        binder(), Key.get(SocketFactory.class, SocketFactoryInstance.class))
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws Exception {
    configureMockSocket(serverInfoResponse);

    NetworkService service = TestHelper.createRocketMQService(mockCallbackServer);
    TargetInfo target = TargetInfo.getDefaultInstance();

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            TestHelper.buildValidDetectionReportCritical(target, service, fakeUtcClock));
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws Exception {
    configureMockSocket(serverInfoResponse);

    NetworkService service = TestHelper.createRocketMQService(mockCallbackServer);

    TargetInfo target = TargetInfo.getDefaultInstance();
    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private void configureMockSocket(String response) throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(response.getBytes(UTF_8)));
  }
}
