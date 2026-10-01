import { ResponseEnvelope } from './types';

export function validateResponseEnvelope(response: any): asserts response is ResponseEnvelope {
  if (typeof response !== 'object' || response === null) {
    throw new Error('Invalid response envelope: not an object');
  }

  if (typeof response.status !== 'number') {
    throw new Error('Invalid response envelope: status is not a number');
  }

  if (typeof response.data !== 'object' || response.data === null) {
    throw new Error('Invalid response envelope: data is not an object');
  }

  if (typeof response.data.userId !== 'string') {
    throw new Error('Invalid response envelope: userId is not a string');
  }

  if (typeof response.data.token !== 'string') {
    throw new Error('Invalid response envelope: token is not a string');
  }

  // Add more validation as necessary based on the actual response structure
}
