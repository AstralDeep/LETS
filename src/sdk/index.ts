import { validateResponseEnvelope } from './responseValidator';
import { ResponseEnvelope } from './types';

export function getSdkResponse(response: any): ResponseEnvelope {
  validateResponseEnvelope(response);
  return response;
}

// Example usage
// const sdkResponse = getSdkResponse(apiResponse);
