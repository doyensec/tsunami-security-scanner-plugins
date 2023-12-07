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
                    && response.headers().firstValue(SERVER_HEADER).equals(RSTUDIO_HEADER)
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
            String body = response.body()
            String exp = body.split(":")[0]
            String mod = body.split(":")[1] 
            logger.atInfo().log("Exp: %s, Mod: %s", exp, mod);   
            
            url = buildTargetUrl(networkService, "/auth-do-sign-in");
            logger.atInfo().log(
                "url: %s, username: %s, password: %s",
                url, credential.username(), credential.password().orElse(""));
            HttpResponse response = sendRequestWithCredentials(url, credential, exp, mod);
            
            return response.status().isSuccess()
                && response
                .bodyString()
                .map(RStudioCredentialTester::bodyContainsSuccessfulLoginElements)
                .orElse(false);
        } catch (IOException e) {
            logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
            return false;
        }
    }

    private HttpResponse sendRequestWithCredentials(String url, TestCredential credential, String exp, String mod){
        
    }


}