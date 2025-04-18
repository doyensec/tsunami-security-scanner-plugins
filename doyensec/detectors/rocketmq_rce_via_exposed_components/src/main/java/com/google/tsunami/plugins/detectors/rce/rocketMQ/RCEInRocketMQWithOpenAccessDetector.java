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
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A Tsunami plugin that detects RCE in RocketMQ exposed broker */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RCEInRocketMQWithOpenAccessDetector",
    version = "0.1",
    description = "This plugin detects RCE in RocketMQ exposed broker",
    author = "Alessandro Versari (alessandro.versari@doyensec.com)",
    bootstrapModule = RCEInRocketMQWithOpenAccessBootstrapModule.class)
public final class RCEInRocketMQWithOpenAccessDetector implements VulnDetector {

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "ROCKET_MQ_WITH_OPEN_ACCESS";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE = "RocketMq Open Access Remote Code Execution";

  @VisibleForTesting static final String VULNERABILITY_REPORT_DESCRIPTION = "";

  @VisibleForTesting static final String VULNERABILITY_REPORT_RECOMMENDATION = "";

  @VisibleForTesting static final String VULNERABILITY_REPORT_DETAILS = "";

  Severity vulnSeverity = Severity.CRITICAL;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private String PAYLOAD_TEMPLATE = "";

  @Inject
  RCEInRocketMQWithOpenAccessDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("RCEInRocketMQWithOpenAccessDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isRocketMQBroker)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  // Checks whether a given service is a rocketMQ  broker
  private boolean isRocketMQBroker(NetworkService networkService) {
    // TODO: implement
    return false;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    // Generate the payload for the callback server
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();

    String oobCallbackUrl = "";
    Payload payload = null;

    // Check if the callback server is available, fallback to response matching if not
    try {
      payload = this.payloadGenerator.generate(config);
      // Use callback for RCE confirmation and raise severity on success
      if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
        logger.atWarning().log(
            "Tsunami Callback Server not available: detector will use response matching only.");
      } else {
        oobCallbackUrl = payload.getPayload();
      }
    } catch (NotImplementedException e) {
      return false;
    }

    String rmiPayload = PAYLOAD_TEMPLATE.replace("HOST", oobCallbackUrl);
    String jsonPayload = getJsonPayload(rmiPayload);

    // Send the malicious HTTP request
    // TODO: add correct uri
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "something";
    logger.atInfo().log("Sending payload to '%s'", targetUri);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(jsonPayload))
            .build();

    try {
      this.httpClient.send(req, networkService);
    } catch (IOException e) {
      e.printStackTrace();
    }
    // payload should never be null here as we should have already returned in that case
    verify(payload != null);
    if (payload.checkIfExecuted()) {
      logger.atInfo().log("Vulnerability confirmed via Callback Server.");
      return true;
    } else {
      logger.atInfo().log(
          "Callback not received and response does not match vulnerable instance, instance is not"
              + " vulnerable.");
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
}
