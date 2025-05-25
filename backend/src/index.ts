import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(cors({
  origin: 'http://localhost:5173'
}));
app.use(express.json());

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from backend!' });
});

app.post('/api/check-phishing', async (req, res) => {
  const { url } = req.body;
  const PHISHTANK_API_KEY = process.env.PHISHTANK_API_KEY || '';

  try {
    const params: Record<string, string> = {
      url,
      format: 'json',
    };
    if (PHISHTANK_API_KEY) {
      params.app_key = PHISHTANK_API_KEY;
    }

    const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'phishtank/davidconselvan'
      },
      body: new URLSearchParams(params)
    });

    const text = await response.text();

    if (!response.ok) {
      throw new Error(`PhishTank responded with status ${response.status}: ${text}`);
    }

    if (!response.headers.get('content-type')?.includes('application/json')) {
      throw new Error(`PhishTank did not return JSON: ${text}`);
    }

    const data: any = JSON.parse(text);
    // The structure of the response is a bit nested
    const isPhishing = data.results.in_database && data.results.valid;

    res.json({
      url,
      isPhishing,
      phishtank: data.results
    });
  } catch (error) {
    console.error('PhishTank error:', error);
    res.status(500).json({ error: 'Failed to check PhishTank', details: error instanceof Error ? error.message : error });
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});