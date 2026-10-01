export interface ResponseEnvelope {
  status: number;
  data: {
    userId: string;
    token: string;
    // Add more fields as necessary based on the actual response structure
  };
}
