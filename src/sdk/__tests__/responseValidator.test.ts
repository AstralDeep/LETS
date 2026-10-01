import { validateResponseEnvelope } from '../responseValidator';
import { ResponseEnvelope } from '../types';

describe('validateResponseEnvelope', () => {
  it('should not throw for a valid response envelope', () => {
    const validResponse: ResponseEnvelope = {
      status: 200,
      data: {
        userId: 'user123',
        token: 'abc123',
      },
    };

    expect(() => validateResponseEnvelope(validResponse)).not.toThrow();
  });

  it('should throw for a response envelope with missing fields', () => {
    const invalidResponse = {
      status: 200,
      data: {
        userId: 'user123',
      },
    };

    expect(() => validateResponseEnvelope(invalidResponse)).toThrow('Invalid response envelope: token is not a string');
  });

  it('should throw for a response envelope with incorrect data types', () => {
    const invalidResponse = {
      status: '200',
      data: {
        userId: 'user123',
        token: 'abc123',
      },
    };

    expect(() => validateResponseEnvelope(invalidResponse)).toThrow('Invalid response envelope: status is not a number');
  });

  it('should throw for a response envelope with null or undefined values', () => {
    const invalidResponse = {
      status: 200,
      data: {
        userId: null,
        token: 'abc123',
      },
    };

    expect(() => validateResponseEnvelope(invalidResponse)).toThrow('Invalid response envelope: userId is not a string');
  });
});
