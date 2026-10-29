const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { chromium } = require('playwright');
const Groq = require('groq-sdk');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
const PYTHON_URL = process.env.PYTHON_ENGINE_URL || 'http://127.0.0.1:8000';
const localVault = new Map();

function egressFirewall(payloadString) {
    for (const [token, realValue] of localVault.entries()) {
        if (payloadString.includes(realValue)) return false;
    }
    return true;
}

app.post('/api/agent/step', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });

    let browser, context, page;
    try {
        browser = await chromium.launch({ headless: false });
        context = await browser.newContext();
        page = await context.newPage();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });

        const rawElements = await page.evaluate(() => {
            const nodes = document.querySelectorAll('input, button, textarea, a, [data-sensitive]');
            return Array.from(nodes).map((el, i) => {
                const rect = el.getBoundingClientRect();
                return { 
                    id: i, tag: el.tagName.toLowerCase(), type: el.type || null, 
                    value: el.value || el.innerText || '', attributes: Array.from(el.attributes).map(a => ({ name: a.name, value: a.value })), 
                    bbox: { x: rect.x, y: rect.y, w: rect.width, h: rect.height }
                };
            }).filter(e => e.bbox.w > 0 && e.bbox.h > 0);
        });
        
        const rawScreenshot = (await page.screenshot()).toString('base64');

        const pyRes = await axios.post(`${PYTHON_URL}/api/detect`, { 
            elements: rawElements, screenshot: rawScreenshot 
        });
        
        const detections = pyRes.data.detections;
        let sanitizedDOM = "Interactive Elements:\n";
        
        rawElements.forEach(el => {
            let displayValue = el.value;
            const match = detections.find(d => d.element_id === el.id);
            if (match) {
                const token = `[REDACTED:${match.type}_${el.id}]`;
                localVault.set(token, match.raw_value);
                displayValue = token;
            }
            sanitizedDOM += `[ID: ${el.id}] <${el.tag}> ${displayValue}\n`;
        });

        if (!egressFirewall(sanitizedDOM)) {
            return res.status(403).json({ error: "Egress Firewall Block: PII Leak Detected in payload." });
        }

        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: 'system', content: 'You are an AI Browser Agent. Output strictly JSON: {"action": "CLICK"|"TYPE", "target_id": ID, "value": "text to type"}. Use REDACTED tokens if typing sensitive info.' },
                { role: 'user', content: sanitizedDOM }
            ],
            model: 'openai/gpt-oss-120b',
            response_format: { type: 'json_object' }
        });

        const agentDecision = JSON.parse(chatCompletion.choices[0].message.content);
        if (agentDecision.action === 'TYPE' && localVault.has(agentDecision.value)) {
            agentDecision.value = localVault.get(agentDecision.value);
        }

        res.json({
            raw_screenshot: `data:image/png;base64,${rawScreenshot}`,
            sanitized_screenshot: pyRes.data.sanitized_screenshot,
            detections,
            agent_decision: agentDecision
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    } finally {
        if (browser) await browser.close();
    }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Agent Core running on port ${PORT}`));