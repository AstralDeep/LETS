import { ResponseEnvelope } from '../types';

export const validApiResponse: ResponseEnvelope = {
  status: 200,
  data: {
    userId: 'user123',
    token: 'abc123',
  },
};

export const invalidApiResponse = {
  status: '200',
  data: {
    userId: 'user123',
  },
};
