import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { z } from 'zod';
import fetch from 'node-fetch';
import multer from 'multer';
import fs from 'fs';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: 'uploads/' });

const schema = z.object({
  url: z.string().url({ message: 'Invalid URL format' }),
});

// URL SCAN
app.post('/api/scan', async (req, res) => {
  const parse = schema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: parse.error.issues[0].message });
  }

  const { url } = parse.data;

  try {
    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': process.env.VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    const { data } = await response.json();
    const analysisId = data.id;

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': process.env.VT_API_KEY,
      },
    });

    const result = await resultResponse.json();
    const stats = result.data.attributes.stats;
    const malicious = stats.malicious || 0;

    res.json({
      status: malicious > 0 ? 'malicious' : 'clean',
      detectedBy: malicious,
    });
  } catch (err) {
    res.status(500).json({ error: 'Network issue' });
  }
});

// FILE SCAN
app.post('/api/scan-file', upload.single('file'), async (req, res) => {
  try {
    const fileStream = fs.createReadStream(req.file.path);

    const response = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': process.env.VT_API_KEY,
      },
      body: fileStream,
    });

    const { data } = await response.json();
    const analysisId = data.id;

    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': process.env.VT_API_KEY,
      },
    });

    const result = await resultResponse.json();
    const stats = result.data.attributes.stats;
    const malicious = stats.malicious || 0;

    // cleanup uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      status: malicious > 0 ? 'malicious' : 'clean',
      detectedBy: malicious,
    });
  } catch (err) {
    res.status(500).json({ error: 'File scan failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
