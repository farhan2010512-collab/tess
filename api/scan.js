export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle preflight request
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // API Key langsung di sini
  const API_KEY = "4f4a6df58b549868e190a4c2c6d34c5370d6e0e0e1d19a5fbbcff420ae5c8b6a";

  if (req.method === 'POST') {
    try {
      const { type, data, analysisId } = req.body;

      if (type === 'scan-url') {
        // Submit URL for scanning
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: {
            "x-apikey": API_KEY,
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded"
          },
          body: `url=${encodeURIComponent(data)}`
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const result = await response.json();
        res.status(200).json(result);

      } else if (type === 'get-analysis') {
        // Get analysis results
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          method: "GET",
          headers: {
            "x-apikey": API_KEY,
            "accept": "application/json"
          }
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const result = await response.json();
        res.status(200).json(result);

      } else {
        res.status(400).json({ error: "Invalid request type" });
      }

    } catch (error) {
      console.error("API Error:", error);
      res.status(500).json({ 
        error: error.message || "Internal server error"
      });
    }
  } else {
    res.status(405).json({ error: "Method not allowed" });
  }
          }
