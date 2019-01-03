package com.jwtauthentication.dto.response;

import org.apache.log4j.Logger;
import org.springframework.context.MessageSource;

public class ApiResponse {

	private String resultCode;
	private String resultDescription;

	public String getResultCode() {
		return resultCode;
	}

	public void setResultCode(String resultCode) {
		this.resultCode = resultCode;
	}

	public String getResultDescription() {
		return resultDescription;
	}

	public void setResultDescription(String resultDescription) {
		this.resultDescription = resultDescription;
	}

	public static ApiResponse getApiResponse(String resultCode, String resultDescription, MessageSource messageSource, Logger log) {

		ApiResponse apiResponse = new ApiResponse();
		apiResponse.setResultCode(resultCode);

		String description = messageSource.getMessage(resultDescription, null, null);
		apiResponse.setResultDescription(description);

		log.info(description);

		return apiResponse;
	}
}
