function uploadFile() {
    const fileInput = document.getElementById('pcapFile');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Veuillez sélectionner un fichier d\'abord');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => displayResults(data))
    .catch(error => console.error('Erreur:', error));
}

function checkVirusTotal() {
    const statistics = document.getElementById('statistics');
    const threatResults = document.getElementById('threatResults');
    
    // Vérifier si des résultats sont disponibles
    if (!statistics.innerHTML) {
        alert('Veuillez analyser un fichier PCAP d\'abord');
        return;
    }

    // Récupérer toutes les IPs (source et destination)
    const sourceIps = Array.from(statistics.querySelectorAll('.ip-address'))
        .map(el => el.textContent);

    if (sourceIps.length === 0) {
        threatResults.innerHTML = '<p class="error">Aucune IP trouvée à analyser</p>';
        return;
    }

    // Afficher un message de chargement avec compteur
    threatResults.innerHTML = `
        <div class="loading">
            <p>Analyse des IPs avec VirusTotal...</p>
            <p>Traitement de l\'IP: <span id="progress">0</span>/${sourceIps.length}</p>
        </div>
    `;

    // Analyser les IPs une par une pour éviter les limites d'API
    let processed = 0;
    const results = [];

    function analyzeNextIp(index) {
        if (index >= sourceIps.length) {
            displayFinalResults(results);
            return;
        }

        const ip = sourceIps[index];
        fetch('/check_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        })
        .then(response => response.json())
        .then(data => {
            processed++;
            document.getElementById('progress').textContent = processed;
            
            if (!data.error) {
                results.push(data);
                displayThreatLevel(data);
            }
            
            // Attendre 1 seconde avant la prochaine requête
            setTimeout(() => analyzeNextIp(index + 1), 1000);
        })
        .catch(error => {
            console.error('Erreur lors de la vérification de l\'IP:', error);
            setTimeout(() => analyzeNextIp(index + 1), 1000);
        });
    }

    // Démarrer l'analyse
    analyzeNextIp(0);
}

function displayFinalResults(results) {
    const threatResults = document.getElementById('threatResults');
    if (results.length === 0) {
        threatResults.innerHTML = '<p class="error">Aucun résultat trouvé depuis VirusTotal</p>';
        return;
    }

    const summary = document.createElement('div');
    summary.className = 'analysis-summary';
    summary.innerHTML = `
        <h3>Analyse Terminée</h3>
        <p>Total des IPs analysées: ${results.length}</p>
        <p>IPs à Risque Élevé: ${results.filter(r => r.threat_level === 'High').length}</p>
        <p>IPs à Risque Moyen: ${results.filter(r => r.threat_level === 'Medium').length}</p>
        <p>IPs à Faible Risque: ${results.filter(r => r.threat_level === 'Low').length}</p>
    `;
    
    threatResults.prepend(summary);
}

function fetchPcapFromAPI() {
    fetch('/fetch_pcap')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayResults(data.results);
                alert('Fichier PCAP récupéré et analysé avec succès: ' + data.filename);
            } else {
                alert('Erreur lors de la récupération du fichier PCAP: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert('Erreur lors de la récupération du fichier PCAP depuis l\'API');
        });
}

function displayResults(data) {
    const statistics = document.getElementById('statistics');
    statistics.innerHTML = `
        <div class="analysis-summary">
            <h3>Résumé de l'Analyse</h3>
            <p><strong>Paquets Total:</strong> ${data.total_packets}</p>
            <p><strong>Analysé le:</strong> ${new Date().toLocaleString('fr-FR')}</p>
            
            <div class="threat-summary">
                <h3>Résumé des Menaces</h3>
                <p class="threat-level-high">IPs à Risque Élevé: ${data.threat_analysis?.high_risk?.length || 0}</p>
                <p class="threat-level-medium">IPs à Risque Moyen: ${data.threat_analysis?.medium_risk?.length || 0}</p>
                <p class="threat-level-low">IPs à Faible Risque: ${data.threat_analysis?.low_risk?.length || 0}</p>
            </div>
        </div>
        
        <div class="ip-analysis">
            <h3>IPs Sources Principales:</h3>
            <ul>
                ${Object.entries(data.ip_sources)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5)
                    .map(([ip, count]) => 
                        `<li><span class="ip-address">${ip}</span>: <span class="count">${count} paquets</span></li>`
                    ).join('')}
            </ul>
            
            <h3>IPs Destinations Principales:</h3>
            <ul>
                ${Object.entries(data.ip_destinations)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5)
                    .map(([ip, count]) => 
                        `<li><span class="ip-address">${ip}</span>: <span class="count">${count} paquets</span></li>`
                    ).join('')}
            </ul>
        </div>
        
        <div class="infection-analysis">
            <h3>Analyse des Infections</h3>
            ${createInfectionSummary(data.infection_analysis)}
        </div>
    `;

    // Ajouter l'analyse des utilisateurs
    if (data.user_analysis) {
        statistics.innerHTML += `
            <div class="user-analysis">
                <h3>Analyse des Utilisateurs</h3>
                <div class="legitimate-users">
                    <h4>Utilisateurs Légitimes (${data.user_analysis.legitimate_users.length})</h4>
                    <ul>
                        ${data.user_analysis.legitimate_users.map(user => `
                            <li class="user-legitimate">
                                <strong>IP:</strong> ${user.ip}
                                <br>
                                <small>Paquets: ${user.packet_count}, 
                                Destinations: ${user.unique_destinations}</small>
                            </li>
                        `).join('')}
                    </ul>
                </div>
                
                <div class="suspicious-users">
                    <h4>Utilisateurs Suspects (${data.user_analysis.suspicious_users.length})</h4>
                    <ul>
                        ${data.user_analysis.suspicious_users.map(user => `
                            <li class="user-suspicious">
                                <strong>IP:</strong> ${user.ip}
                                <br>
                                <small>Raisons: ${user.reasons.join(', ')}</small>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            </div>
        `;
    }

    const threatResults = document.getElementById('threatResults');
    if (data.threat_analysis) {
        let threatHtml = '<div class="threat-analysis">';
        
        if (data.threat_analysis.high_risk.length > 0) {
            threatHtml += '<h3 class="threat-level-high">IPs à Risque Élevé</h3>';
            data.threat_analysis.high_risk.forEach(threat => {
                threatHtml += createThreatCard(threat);
            });
        }
        
        if (data.threat_analysis.medium_risk.length > 0) {
            threatHtml += '<h3 class="threat-level-medium">IPs à Risque Moyen</h3>';
            data.threat_analysis.medium_risk.forEach(threat => {
                threatHtml += createThreatCard(threat);
            });
        }
        
        if (data.threat_analysis.low_risk.length > 0) {
            threatHtml += '<h3 class="threat-level-low">IPs à Faible Risque</h3>';
            data.threat_analysis.low_risk.forEach(threat => {
                threatHtml += createThreatCard(threat);
            });
        }
        
        threatHtml += '</div>';
        threatResults.innerHTML = threatHtml;
    }
}

function createInfectionSummary(infectionData) {
    if (!infectionData) return '';

    let flagHtml = '';
    if (infectionData.potential_flag && infectionData.flag_evidence) {
        const evidence = infectionData.flag_evidence;
        flagHtml = `
            <div class="flag-alert">
                <h4>🚨 FLAG DÉTECTÉ 🚨</h4>
                <p class="flag-ip">Machine Infectée: ${infectionData.potential_flag}</p>
                <div class="flag-details">
                    <p><strong>Score de détection:</strong> ${evidence.score}/7</p>
                    <p><strong>Preuves d'infection:</strong></p>
                    <ul>
                        ${evidence.reasons.map(reason => `<li>${reason}</li>`).join('')}
                    </ul>
                    <p><strong>Première activité:</strong> ${new Date(evidence.timestamp_first * 1000).toLocaleString('fr-FR')}</p>
                    <p><strong>Dernière activité:</strong> ${new Date(evidence.timestamp_last * 1000).toLocaleString('fr-FR')}</p>
                    <p><strong>Durée de l'infection:</strong> ${Math.round(evidence.duration / 60)} minutes</p>
                    <p><strong>Données transférées:</strong> ${formatBytes(evidence.data_transferred)}</p>
                    <p><strong>Nombre de connexions:</strong> ${evidence.connection_count}</p>
                    <p><strong>Destinations uniques:</strong> ${evidence.unique_destinations}</p>
                </div>
            </div>
        `;
    }

    return `
        <div class="infection-summary">
            ${flagHtml}
            <h4>Sources Malveillantes Détectées</h4>
            <ul class="malicious-sources">
                ${infectionData.malicious_sources.map(ip => `
                    <li class="threat-level-high">
                        <strong>IP Source:</strong> ${ip}
                    </li>
                `).join('')}
            </ul>

            <h4>Machines Potentiellement Infectées</h4>
            <ul class="infected-machines">
                ${infectionData.infected_machines.map(ip => `
                    <li class="threat-level-medium">
                        <strong>IP Machine:</strong> ${ip}
                    </li>
                `).join('')}
            </ul>

            <h4>Modèles de Connexions Suspectes</h4>
            <ul class="suspicious-patterns">
                ${infectionData.suspicious_patterns.map(pattern => `
                    <li>
                        <strong>Type:</strong> ${pattern.type}<br>
                        <strong>Source:</strong> ${pattern.source}<br>
                        <strong>Destination:</strong> ${pattern.destination}<br>
                        <strong>Nombre de connexions:</strong> ${pattern.count}
                    </li>
                `).join('')}
            </ul>
        </div>
    `;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function createThreatCard(threat) {
    return `
        <div class="threat-result">
            <p><strong>IP:</strong> ${threat.ip}</p>
            <p><strong>Niveau de Menace:</strong> ${translateThreatLevel(threat.threat_level)}</p>
            <p><strong>Détections:</strong> ${threat.detections}</p>
            ${threat.details ? `
                <ul>
                    <li>URLs Détectées: ${threat.details.detected_urls || 0}</li>
                    <li>Échantillons Détectés: ${threat.details.detected_samples || 0}</li>
                    <li>Pays: ${threat.details.country || 'Inconnu'}</li>
                </ul>
            ` : ''}
        </div>
    `;
}

function translateThreatLevel(level) {
    const translations = {
        'High': 'Élevé',
        'Medium': 'Moyen',
        'Low': 'Faible',
        'Unknown': 'Inconnu'
    };
    return translations[level] || level;
}

function displayThreatLevel(data) {
    const threatResults = document.getElementById('threatResults');
    const threatClass = `threat-level-${(data.threat_level || 'unknown').toLowerCase()}`;
    
    const threatElement = document.createElement('div');
    threatElement.className = 'threat-result';
    threatElement.innerHTML = `
        <p><strong>IP:</strong> ${data.ip}</p>
        <p><strong>Niveau de Menace:</strong> <span class="${threatClass}">${translateThreatLevel(data.threat_level)}</span></p>
        <p><strong>Total des Détections:</strong> ${data.detections}</p>
        ${data.details ? `
            <p><strong>Détails:</strong></p>
            <ul>
                <li>URLs Détectées: ${data.details.detected_urls || 0}</li>
                <li>Échantillons Détectés: ${data.details.detected_samples || 0}</li>
                <li>Pays: ${data.details.country || 'Inconnu'}</li>
                <li>Propriétaire AS: ${data.details.as_owner || 'Inconnu'}</li>
            </ul>
        ` : ''}
        <hr>
    `;
    
    threatResults.appendChild(threatElement);
}
