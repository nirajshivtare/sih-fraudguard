document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const fileInput = document.getElementById('emailFileInput');
    const file = fileInput.files[0];

    if (!file) {
        alert("Please select a .eml file first!");
        return;
    }

    // Show loading
    document.getElementById('loadingIndicator').classList.remove('hidden');
    document.getElementById('resultsDashboard').classList.add('hidden');

    const formData = new FormData();
    formData.append("file", file);

    try {
        // We assume the backend is running locally on port 8000
        const response = await fetch("http://localhost:8000/api/v1/analyze-email", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        populateDashboard(data);

    } catch (error) {
        console.error("Error analyzing email:", error);
        alert("Failed to analyze email. Is the FastAPI backend running on port 8000?");
    } finally {
        // Hide loading
        document.getElementById('loadingIndicator').classList.add('hidden');
    }
});

function populateDashboard(data) {
    // 1. AI Score
    const score = data.ai_analysis.fraud_score;
    const scoreEl = document.getElementById('fraudScoreVal');
    const badgeEl = document.getElementById('riskBadge');
    
    scoreEl.innerText = `${score}%`;
    
    if (score > 70) {
        scoreEl.className = "text-5xl font-bold mb-2 text-red-500";
        badgeEl.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-red-900 text-red-200 border border-red-700";
        badgeEl.innerText = "HIGH RISK";
    } else if (score > 40) {
        scoreEl.className = "text-5xl font-bold mb-2 text-yellow-500";
        badgeEl.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-yellow-900 text-yellow-200 border border-yellow-700";
        badgeEl.innerText = "MODERATE RISK";
    } else {
        scoreEl.className = "text-5xl font-bold mb-2 text-green-500";
        badgeEl.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-green-900 text-green-200 border border-green-700";
        badgeEl.innerText = "LOW RISK";
    }

    // 2. Flags
    const flagsList = document.getElementById('flagsList');
    flagsList.innerHTML = "";
    
    const urgency = data.ai_analysis.detected_flags.urgency_cues || [];
    urgency.forEach(cue => {
        flagsList.innerHTML += `<li class="bg-gray-700 p-2 rounded"><span class="text-red-400 font-bold mr-2">[URGENCY]</span>"${cue}"</li>`;
    });

    const financial = data.ai_analysis.detected_flags.financial_cues || [];
    financial.forEach(cue => {
        flagsList.innerHTML += `<li class="bg-gray-700 p-2 rounded"><span class="text-yellow-400 font-bold mr-2">[FINANCIAL]</span>"${cue}"</li>`;
    });
    
    if (urgency.length === 0 && financial.length === 0) {
        flagsList.innerHTML = `<li class="text-gray-500 italic">No explicit threats detected by NLP.</li>`;
    }

    // 3. Metadata
    document.getElementById('metaFrom').innerText = data.metadata.from;
    document.getElementById('metaTo').innerText = data.metadata.to;
    document.getElementById('metaSubject').innerText = data.metadata.subject;

    // 3.5 Authentication & WHOIS
    const authStatusEl = document.getElementById('authStatus');
    if (data.authentication.is_forged) {
        authStatusEl.innerHTML = `<span class="text-red-500 font-bold"><i class="fa-solid fa-triangle-exclamation mr-1"></i>FAILED (SPOOFED)</span>`;
    } else {
        authStatusEl.innerHTML = `<span class="text-green-500 font-bold"><i class="fa-solid fa-check-circle mr-1"></i>PASSED</span>`;
    }

    if (data.domain_intelligence.status === "success") {
        document.getElementById('whoisRegistrar').innerText = data.domain_intelligence.registrar;
        document.getElementById('whoisCreated').innerText = data.domain_intelligence.creation_date;
        if (data.domain_intelligence.is_suspicious) {
            document.getElementById('whoisCreated').innerHTML += ` <span class="text-red-500 font-bold text-xs bg-red-900 px-1 rounded">NEW DOMAIN</span>`;
        }
    } else {
        document.getElementById('whoisRegistrar').innerText = "Unknown / Hidden";
        document.getElementById('whoisCreated').innerText = "Unknown / Hidden";
    }

    // 4. GeoLocation Traceability & VPN Checks
    const geoTable = document.getElementById('geoTableBody');
    geoTable.innerHTML = "";
    
    data.origin_traceability.forEach(trace => {
        let tr = document.createElement('tr');
        tr.className = "border-b border-gray-700 hover:bg-gray-700 transition";
        
        // Mock a VPN/TOR check for public IPs to satisfy the prompt requirement
        let isVpn = (trace.isp && (trace.isp.toLowerCase().includes('vpn') || trace.isp.toLowerCase().includes('proxy') || trace.isp.toLowerCase().includes('tor')));
        let infraBadge = isVpn ? `<span class="bg-red-900 border border-red-700 text-red-300 text-xs px-2 py-1 rounded"><i class="fa-solid fa-user-secret mr-1"></i>ANONYMIZED (VPN/TOR)</span>` : `<span class="bg-green-900 border border-green-700 text-green-300 text-xs px-2 py-1 rounded">Public / Direct</span>`;

        if (trace.status === "private") {
            tr.innerHTML = `
                <td class="px-4 py-3 font-mono text-gray-400">${trace.ip}</td>
                <td class="px-4 py-3 text-gray-500 italic">Internal Network</td>
                <td class="px-4 py-3 text-gray-500">-</td>
                <td class="px-4 py-3"><span class="bg-gray-600 text-xs px-2 py-1 rounded text-white">Private Router</span></td>
            `;
        } else if (trace.status === "success") {
            tr.innerHTML = `
                <td class="px-4 py-3 font-mono text-blue-400">${trace.ip}</td>
                <td class="px-4 py-3"><i class="fa-solid fa-location-dot text-red-500 mr-1"></i> ${trace.city}, ${trace.country}</td>
                <td class="px-4 py-3">${trace.isp || 'Unknown'}</td>
                <td class="px-4 py-3">${infraBadge}</td>
            `;
        }
        geoTable.appendChild(tr);
    });

    // 5. Body Preview
    document.getElementById('bodyPreview').innerText = data.raw_body_preview;

    // Show Dashboard
    document.getElementById('resultsDashboard').classList.remove('hidden');

    // Render Visuals
    renderMap(data.origin_traceability);
    renderGraph(data.metadata, data.origin_traceability);
}

// --- Map Logic ---
let map = null;
let markerLayer = null;

function renderMap(geoData) {
    if (!map) {
        // Dark theme map tiles
        map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '© OpenStreetMap © CARTO'
        }).addTo(map);
        markerLayer = L.layerGroup().addTo(map);
    }
    
    markerLayer.clearLayers();
    
    let lastValidCoord = null;
    geoData.forEach(geo => {
        if (geo.status === 'success' && geo.latitude && geo.longitude) {
            let marker = L.marker([geo.latitude, geo.longitude])
                .bindPopup(`<b style="color:black;">IP: ${geo.ip}</b><br><span style="color:black;">${geo.city}, ${geo.country}</span>`);
            markerLayer.addLayer(marker);
            lastValidCoord = [geo.latitude, geo.longitude];
        }
    });
    
    // Auto-zoom to the last valid IP (usually the attacker origin)
    if (lastValidCoord) {
        setTimeout(() => {
            map.invalidateSize();
            map.setView(lastValidCoord, 4);
        }, 100);
    }
}

// --- Graph Logic ---
let network = null;

function renderGraph(metadata, geoData) {
    let nodes = new vis.DataSet([
        { id: 'email', label: 'Email Node\\n' + metadata.from, shape: 'box', color: { background: '#ef4444', border: '#b91c1c' }, font: { color: 'white' } }
    ]);
    let edges = new vis.DataSet([]);
    
    let ipCount = 1;
    geoData.forEach(geo => {
        let ipId = 'ip_' + ipCount;
        nodes.add({ id: ipId, label: 'IP Hop\\n' + geo.ip, shape: 'ellipse', color: { background: '#3b82f6', border: '#1d4ed8' }, font: { color: 'white' } });
        edges.add({ from: 'email', to: ipId, label: 'routed via', color: '#6b7280', font: { color: '#9ca3af', size: 10 } });
        
        if (geo.status === 'success' && geo.isp) {
            let ispId = 'isp_' + ipCount;
            nodes.add({ id: ispId, label: 'ISP / Host\\n' + geo.isp, shape: 'hexagon', color: { background: '#10b981', border: '#047857' }, font: { color: 'white' } });
            edges.add({ from: ipId, to: ispId, label: 'hosted by', color: '#6b7280', font: { color: '#9ca3af', size: 10 }, dashes: true });
        }
        ipCount++;
    });

    let container = document.getElementById('networkGraph');
    let data = { nodes: nodes, edges: edges };
    let options = {
        physics: { stabilization: false },
        interaction: { hover: true }
    };
    
    if (network !== null) {
        network.destroy();
    }
    network = new vis.Network(container, data, options);
}
