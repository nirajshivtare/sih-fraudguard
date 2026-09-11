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
        const response = await fetch("https://fraudguard-backend-3ebf.onrender.com/api/v1/analyze-email", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        populateDashboard(data);

    } catch (error) {
        document.getElementById('loadingIndicator').classList.add('hidden');
        alert("Error analyzing email: " + error.message);
    } finally {
        // Hide loading
        document.getElementById('loadingIndicator').classList.add('hidden');
    }
});

function populateDashboard(data) {
    // 1. Fraud Risk Score & Origin Confidence
    const riskScore = data.scoring.fraud_risk.score;
    const originScore = data.scoring.origin_confidence.score;
    
    document.getElementById('fraudScoreVal').innerText = `${riskScore}%`;
    document.getElementById('originScoreVal').innerText = `${originScore}%`;
    
    const riskBadge = document.getElementById('riskBadge');
    if (riskScore > 75) {
        riskBadge.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-red-900 text-red-200 border border-red-700";
        riskBadge.innerText = "CRITICAL RISK";
    } else if (riskScore > 50) {
        riskBadge.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-orange-900 text-orange-200 border border-orange-700";
        riskBadge.innerText = "HIGH RISK";
    } else if (riskScore > 20) {
        riskBadge.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-yellow-900 text-yellow-200 border border-yellow-700";
        riskBadge.innerText = "MEDIUM RISK";
    } else {
        riskBadge.className = "inline-block px-3 py-1 rounded-full text-sm font-bold bg-green-900 text-green-200 border border-green-700";
        riskBadge.innerText = "LOW RISK";
    }

    // 2. Evidence Flags (Why this score?)
    const flagsList = document.getElementById('flagsList');
    flagsList.innerHTML = "";
    
    data.scoring.fraud_risk.evidence_risk.forEach(cue => {
        flagsList.innerHTML += `<li class="bg-red-900/50 p-2 rounded text-red-300 font-medium text-sm">${cue}</li>`;
    });
    data.scoring.fraud_risk.evidence_trust.forEach(cue => {
        flagsList.innerHTML += `<li class="bg-green-900/50 p-2 rounded text-green-300 font-medium text-sm">${cue}</li>`;
    });
    data.scoring.origin_confidence.evidence.forEach(cue => {
        flagsList.innerHTML += `<li class="bg-blue-900/50 p-2 rounded text-blue-300 font-medium text-sm">${cue}</li>`;
    });

    // 3. Metadata & Case ID
    document.getElementById('metaFrom').innerText = data.metadata.from;
    document.getElementById('metaTo').innerText = data.metadata.to;
    document.getElementById('metaSubject').innerText = data.metadata.subject;
    document.getElementById('metaMsgId').innerText = data.metadata.message_id || "Not present";
    document.getElementById('metaReturn').innerText = data.metadata.return_path || "Not present";
    document.getElementById('metaMailer').innerText = data.metadata.x_mailer || "Not present";
    document.getElementById('metaOrigIp').innerText = data.metadata.x_originating_ip || "Not present";
    
    // Add Case info
    document.getElementById('caseIdBadge').innerText = "CASE ID: " + data.case_id;

    // 4. Authentication Validation & Alignment
    const authStatusEl = document.getElementById('authStatus');
    authStatusEl.innerHTML = `
        <div class="text-xs space-y-1">
            <div>SPF: <span class="font-bold">${data.authentication.spf}</span></div>
            <div>DKIM: <span class="font-bold">${data.authentication.dkim}</span></div>
            <div>DMARC: <span class="font-bold">${data.authentication.dmarc}</span></div>
            <div>Alignment: <span class="font-bold text-yellow-400">${data.authentication.alignment}</span></div>
        </div>
    `;

    // 5. Domain Intelligence
    if (data.domain_intelligence.status === "success") {
        document.getElementById('whoisRegistrar').innerText = data.domain_intelligence.registrar;
        document.getElementById('whoisCreated').innerText = data.domain_intelligence.creation_date;
        if (data.domain_intelligence.is_suspicious) {
            document.getElementById('whoisCreated').innerHTML += ` <span class="text-red-500 font-bold text-[10px] bg-red-900 px-1 rounded ml-1">NEW DOMAIN</span>`;
        }
    } else {
        document.getElementById('whoisRegistrar').innerText = "DATA UNAVAILABLE";
        document.getElementById('whoisCreated').innerText = "DATA UNAVAILABLE";
    }

    // 6. IOC Table Population
    const iocTable = document.getElementById('iocTableBody');
    iocTable.innerHTML = "";
    
    if (data.iocs.urls && data.iocs.urls.length > 0) {
        data.iocs.urls.forEach(ioc => {
            let tr = document.createElement('tr');
            tr.className = "border-b border-gray-700 hover:bg-gray-700 transition";
            
            let classColor = "text-gray-400";
            if (ioc.classification === "MALICIOUS") classColor = "text-red-500 font-bold";
            if (ioc.classification === "SUSPICIOUS") classColor = "text-yellow-500 font-bold";
            if (ioc.classification === "BENIGN") classColor = "text-green-500 font-bold";
            
            tr.innerHTML = `
                <td class="px-3 py-2 font-mono text-blue-400 break-all max-w-[200px]">${ioc.value}</td>
                <td class="px-3 py-2">${ioc.type}</td>
                <td class="px-3 py-2 ${classColor}">${ioc.classification}</td>
                <td class="px-3 py-2">${ioc.confidence}</td>
                <td class="px-3 py-2 text-gray-400 italic">${ioc.reason}</td>
            `;
            iocTable.appendChild(tr);
        });
    } else {
        iocTable.innerHTML = `<tr><td colspan="5" class="px-3 py-2 text-center text-gray-500 italic">No IOCs extracted</td></tr>`;
    }

    // 7. GeoLocation Traceability & Infrastructure
    const geoTable = document.getElementById('geoTableBody');
    geoTable.innerHTML = "";
    
    data.origin_traceability.forEach(trace => {
        let tr = document.createElement('tr');
        tr.className = "border-b border-gray-700 hover:bg-gray-700 transition";
        
        if (trace.status === "private") {
            tr.innerHTML = `
                <td class="px-4 py-3 font-mono text-gray-400">${trace.ip}</td>
                <td class="px-4 py-3 text-gray-500 italic">Internal Network</td>
                <td class="px-4 py-3 text-gray-500">-</td>
                <td class="px-4 py-3"><span class="bg-gray-600 text-[10px] px-2 py-1 rounded text-white">Private Router</span></td>
            `;
        } else if (trace.status === "success") {
            let isVpn = trace.infrastructure_type !== "Unknown";
            let infraBadge = isVpn ? `<span class="bg-yellow-900 border border-yellow-700 text-yellow-300 text-[10px] px-2 py-1 rounded"><i class="fa-solid fa-cloud mr-1"></i>${trace.infrastructure_type}</span>` : `<span class="bg-green-900 border border-green-700 text-green-300 text-[10px] px-2 py-1 rounded">Direct / ISP</span>`;
            
            tr.innerHTML = `
                <td class="px-4 py-3 font-mono text-blue-400">${trace.ip}</td>
                <td class="px-4 py-3"><i class="fa-solid fa-location-dot text-red-500 mr-1"></i> ${trace.probable_city}, ${trace.probable_country}</td>
                <td class="px-4 py-3 text-xs">${trace.isp || 'Unknown'}</td>
                <td class="px-4 py-3">${infraBadge}</td>
            `;
        }
        geoTable.appendChild(tr);
    });

    // 8. Body Preview
    document.getElementById('bodyPreview').innerText = data.raw_body_preview;

    // Show Dashboard
    document.getElementById('resultsDashboard').classList.remove('hidden');
    document.getElementById('downloadReportBtn').classList.remove('hidden');
    document.getElementById('downloadPdfBtn').classList.remove('hidden');

    currentReportData = data;

    // Render Visuals
    renderMap(data.origin_traceability);
    renderGraph(data.metadata, data.origin_traceability, data.authentication, data.iocs);
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
                .bindPopup(`<b style="color:black;">Observed IP: ${geo.ip}</b><br><span style="color:black;">Probable Location: ${geo.probable_city}, ${geo.probable_country}</span>`);
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

// --- Download Report Logic ---
let currentReportData = null;

document.getElementById('downloadReportBtn').addEventListener('click', () => {
    if (!currentReportData) return;
    
    let reportText = `FRAUDGUARD AI - EMAIL FORENSIC REPORT\n`;
    reportText += `=====================================\n\n`;
    reportText += `CASE ID: ${currentReportData.case_id}\n`;
    reportText += `EVIDENCE SHA-256: ${currentReportData.evidence.sha256}\n\n`;
    
    reportText += `--- 1. SCORING ---\n`;
    reportText += `FRAUD RISK: ${currentReportData.scoring.fraud_risk.score}% (${currentReportData.scoring.fraud_risk.level})\n`;
    reportText += `ORIGIN CONFIDENCE: ${currentReportData.scoring.origin_confidence.score}%\n\n`;
    
    reportText += `--- 2. AUTHENTICATION & ALIGNMENT ---\n`;
    reportText += `SPF: ${currentReportData.authentication.spf}\n`;
    reportText += `DKIM: ${currentReportData.authentication.dkim}\n`;
    reportText += `DMARC: ${currentReportData.authentication.dmarc}\n`;
    reportText += `Alignment: ${currentReportData.authentication.alignment}\n\n`;
    
    reportText += `--- 3. THREAT INTELLIGENCE ---\n`;
    reportText += `Signals: ${JSON.stringify(currentReportData.scoring.fraud_risk.evidence_risk)}\n\n`;
    
    reportText += `--- 4. IOCs ---\n`;
    reportText += `Domains: ${currentReportData.iocs.domains.join(", ")}\n`;
    reportText += `IPs: ${currentReportData.routing.extracted_ips.join(", ")}\n\n`;
    
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Report_${currentReportData.case_id}.txt`;
    a.click();
    window.URL.revokeObjectURL(url);
});

document.getElementById('downloadPdfBtn').addEventListener('click', () => {
    if (!currentReportData || !window.jspdf) {
        alert("PDF generator not ready or no data.");
        return;
    }
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("FRAUDGUARD AI - FORENSIC REPORT", 10, 20);
    
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text(`CASE ID: ${currentReportData.case_id}`, 10, 30);
    doc.text(`EVIDENCE SHA-256: ${currentReportData.evidence.sha256}`, 10, 35);
    
    doc.setFont("helvetica", "bold");
    doc.text("--- 1. SCORING ---", 10, 45);
    doc.setFont("helvetica", "normal");
    doc.text(`FRAUD RISK: ${currentReportData.scoring.fraud_risk.score}% (${currentReportData.scoring.fraud_risk.level})`, 10, 52);
    doc.text(`ORIGIN CONFIDENCE: ${currentReportData.scoring.origin_confidence.score}%`, 10, 57);
    
    doc.setFont("helvetica", "bold");
    doc.text("--- 2. AUTHENTICATION ---", 10, 67);
    doc.setFont("helvetica", "normal");
    doc.text(`SPF: ${currentReportData.authentication.spf}`, 10, 74);
    doc.text(`DKIM: ${currentReportData.authentication.dkim}`, 10, 79);
    doc.text(`DMARC: ${currentReportData.authentication.dmarc}`, 10, 84);
    doc.text(`Alignment: ${currentReportData.authentication.alignment}`, 10, 89);
    
    doc.setFont("helvetica", "bold");
    doc.text("--- 3. IOCs ---", 10, 99);
    doc.setFont("helvetica", "normal");
    
    let y = 106;
    if (currentReportData.iocs.urls && currentReportData.iocs.urls.length > 0) {
        currentReportData.iocs.urls.forEach(u => {
            doc.text(`[${u.classification}] ${u.value.substring(0, 80)}`, 10, y);
            y += 5;
            if(y > 280) { doc.addPage(); y = 20; }
        });
    } else {
        doc.text("No URLs Extracted.", 10, y);
    }
    
    doc.save(`Forensic_Report_${currentReportData.case_id}.pdf`);
});

// --- Graph Logic ---
let network = null;

function renderGraph(metadata, geoData, authData, iocData) {
    let nodes = new vis.DataSet([
        { id: 'email', label: 'Email Node\\n' + metadata.from, shape: 'box', color: { background: '#ef4444', border: '#b91c1c' }, font: { color: 'white' } }
    ]);
    let edges = new vis.DataSet([]);
    
    // Auth Nodes
    nodes.add({ id: 'auth_spf', label: 'SPF\\n' + authData.spf, shape: 'diamond', color: { background: '#f59e0b', border: '#b45309' }, font: { color: 'white' } });
    edges.add({ from: 'email', to: 'auth_spf', label: 'validates', color: '#6b7280', font: { color: '#9ca3af', size: 10 } });
    
    // IP Trace
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

    // IOC Trace
    let urlCount = 1;
    if (iocData && iocData.urls) {
        iocData.urls.forEach(u => {
            if (u.classification === "MALICIOUS" || u.classification === "SUSPICIOUS") {
                let uId = 'url_' + urlCount;
                nodes.add({ id: uId, label: 'URL\\n' + u.domain, shape: 'star', color: { background: '#9333ea', border: '#7e22ce' }, font: { color: 'white' } });
                edges.add({ from: 'email', to: uId, label: 'contains', color: '#6b7280', font: { color: '#9ca3af', size: 10 } });
                urlCount++;
            }
        });
    }

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
