/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.rstudio;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.List;

import org.apache.commons.codec.binary.Base64;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import javax.inject.Inject;

public final class RStudioCredentialTester extends CredentialTester {
    private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
    private final HttpClient httpClient;

    private static final String RSTUDIO_SERVICE = "rstudio";
    private static final String RSTUDIO_HEADER = "RStudio";
    private static final String SERVER_HEADER = "Server";

    @Inject
    RStudioCredentialTester(HttpClient httpClient) {
        this.httpClient = checkNotNull(httpClient);
    }

    @Override
    public String name(){
        return "RStudioCredentialTester";
    }

    @Override
    public String description(){
        return "RStudio credential tester.";
    }

    private static String buildTargetUrl(NetworkService networkService, String path) {
        StringBuilder targetUrlBuilder = new StringBuilder();

        if (NetworkServiceUtils.isWebService(networkService)) {
            targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
        } else {
            // Default to HTTP protocol when the scanner cannot identify the actual service.
            targetUrlBuilder
                .append("http://")
                .append(NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint()))
                .append("/");
        }
        targetUrlBuilder.append(path);
        return targetUrlBuilder.toString();
    }

    @Override
    public boolean canAccept(NetworkService networkService){
        boolean canAcceptByNmapReport = NetworkServiceUtils.getWebServiceName(networkService).equals(RSTUDIO_SERVICE);
        if (canAcceptByNmapReport) {
            return true;
        }
        boolean canAcceptByCustomFingerprint = false;
        String url = buildTargetUrl(networkService, "");
        try {
            logger.atInfo().log("Probing RStudio - custom fingerprint phase");
            HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());
            canAcceptByCustomFingerprint =
                response.status().isSuccess()
                    && response.headers().firstValue(SERVER_HEADER).equals(RSTUDIO_HEADER);
        } catch (IOException e) {
            logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
            return false;
        }
        return canAcceptByCustomFingerprint;
    } 

    @Override
    public ImmutableList<TestCredential> testValidCredentials(
        NetworkService networkService, List<TestCredential> credentials) {

        return credentials.stream()
            .filter(cred -> isRStudioAccessible(networkService, cred))
            .collect(toImmutableList());
    } 

    //miss to encrypt the parameter and to check when we have successfully performed the login
    private boolean isRStudioAccessible(NetworkService networkService, TestCredential credential) {
        var url = buildTargetUrl(networkService, "/auth-public-key");
        try {
            logger.atInfo().log("Retrieving public key");
            HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());
            Optional<String> body = response.bodyString();
            String exponent = body.get().split(":")[0];
            String modulus = body.get().split(":")[1];
            logger.atInfo().log("Exp: %s, Mod: %s", exponent, modulus);   
            
            url = buildTargetUrl(networkService, "/auth-do-sign-in");
            logger.atInfo().log(
                "url: %s, username: %s, password: %s",
                url, credential.username(), credential.password().orElse(""));
            response = sendRequestWithCredentials(url, credential, exponent, modulus);
            
            return response.status().isRedirect()
                && response.headers().get("Set-Cookie").isPresent();
        } catch (IOException e) {
            logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
            return false;
        }
    }

    private HttpResponse sendRequestWithCredentials(String url, TestCredential credential, String exponent, String modulus)
        throws NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, InvalidKeySpecException, IOException{
        //encrypting with RSA PCKS#1 version 2
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
            new BigInteger(modulus,16), 
            new BigInteger(exponent,16));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        StringBuilder sb = new StringBuilder();
        sb.append(credential.username());
        sb.append("\n");
        sb.append(credential.password());
        byte[] cipherData = cipher.doFinal(sb.toString().getBytes());

        //converting the ciphertext to hex
        sb = new StringBuilder();
        for (byte b : cipherData) {
            sb.append(String.format("%02X ", b));
        }

        //now converting the hex to base64
        byte[] data = Base64.encodeBase64(sb.toString().getBytes());
        String ciphertext = new String(data, StandardCharsets.UTF_8);
        logger.atInfo().log("Encrypted. Ciphertext %s", ciphertext);

        var headers = HttpHeaders.builder()
            .addHeader("Cookie", "rs-csrf-token=1")
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .build();

        sb = new StringBuilder();
        sb.append("rs-csrf-token=1&");
        sb.append("v="+ciphertext);
        return httpClient.send(post(url).setHeaders(headers).setRequestBody(ByteString.copyFrom(sb.toString().getBytes())).build());
    }

}