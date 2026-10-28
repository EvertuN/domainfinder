// DomainFinder Frontend Logic (Sem piscar a tela, com atualização cirúrgica in-place)

document.addEventListener('DOMContentLoaded', function () {
    // DOM Elements - Input & Upload
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const btnSelectFile = document.getElementById('btnSelectFile');
    const selectedFileInfo = document.getElementById('selectedFileInfo');
    const fileNameDisplay = document.getElementById('fileName');
    const btnRemoveFile = document.getElementById('btnRemoveFile');
    
    const domainForm = document.getElementById('domainForm');
    const domainsText = document.getElementById('domains_text');
    const btnFillDemoText = document.getElementById('btnFillDemoText');
    const btnSubmit = document.getElementById('btnSubmit');
    const btnReset = document.getElementById('btnReset');

    // Collapsible Input & Add Button
    const inputCard = document.getElementById('inputCard');
    const inputCardHeader = document.getElementById('inputCardHeader');
    const collapsedInputBar = document.getElementById('collapsedInputBar');
    const collapsedDomainCount = document.getElementById('collapsedDomainCount');
    const collapsedSourceInfo = document.getElementById('collapsedSourceInfo');
    const btnShowInputCard = document.getElementById('btnShowInputCard');
    const btnHideInputCard = document.getElementById('btnHideInputCard');
    
    // Progress
    const progressSection = document.getElementById('progressSection');
    const progressBar = document.getElementById('progressBar');
    const progressPercentage = document.getElementById('progressPercentage');
    const progressText = document.getElementById('progressText');
    const progressDetail = document.getElementById('progressDetail');
    const btnCancelScan = document.getElementById('btnCancelScan');
    const btnDismissProgress = document.getElementById('btnDismissProgress');
    const progressSpinner = document.getElementById('progressSpinner');
    let progressHideTimer = null;
    
    // Stats
    const statsSection = document.getElementById('statsSection');
    const statTotal = document.getElementById('statTotal');
    const statAvailable = document.getElementById('statAvailable');
    const statRegistered = document.getElementById('statRegistered');
    const statErrors = document.getElementById('statErrors');
    
    // Results & Toolbar
    const resultsSection = document.getElementById('resultsSection');
    const resultsTableBody = document.getElementById('resultsTableBody');
    const noResultsFiltered = document.getElementById('noResultsFiltered');
    const searchFilter = document.getElementById('searchFilter');
    const pageSizeSelect = document.getElementById('pageSizeSelect');
    const filterButtons = document.querySelectorAll('#filterButtonGroup button');
    
    const filterCountAll = document.getElementById('filterCountAll');
    const filterCountAvailable = document.getElementById('filterCountAvailable');
    const filterCountRegistered = document.getElementById('filterCountRegistered');
    
    // Pagination
    const paginationContainer = document.getElementById('paginationContainer');
    const paginationInfo = document.getElementById('paginationInfo');
    
    // Export & Actions
    const btnExportAllCsv = document.getElementById('btnExportAllCsv');
    const btnExportAvailableCsv = document.getElementById('btnExportAvailableCsv');
    const btnCopyAvailable = document.getElementById('btnCopyAvailable');
    
    // Toast
    const toastEl = document.getElementById('notificationToast');
    const toastMessage = document.getElementById('toastMessage');
    const toast = toastEl ? new bootstrap.Toast(toastEl, { delay: 2500 }) : null;

    // Modal
    const whoisModalEl = document.getElementById('whoisDetailModal');
    const whoisModal = whoisModalEl ? new bootstrap.Modal(whoisModalEl) : null;
    let activeModalDomain = null;

    // State
    let allResults = [];
    let filteredResults = [];
    let currentFilter = 'all';
    let searchQuery = '';
    let currentPage = 1;
    let pageSize = 25;
    let sortColumn = null;
    let sortDirection = 'asc';
    let isCancelled = false;
    let isScanning = false;

    // --- 1. File Upload & Drag-and-Drop ---
    if (btnSelectFile && fileInput) {
        btnSelectFile.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }

    if (dropZone) {
        dropZone.addEventListener('click', () => {
            fileInput.click();
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
            });
        });

        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                updateFileDisplay(files[0].name);
            }
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files.length > 0) {
                updateFileDisplay(fileInput.files[0].name);
            }
        });
    }

    if (btnRemoveFile) {
        btnRemoveFile.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.value = '';
            selectedFileInfo.classList.add('d-none');
            btnSelectFile.classList.remove('d-none');
        });
    }

    function updateFileDisplay(name) {
        fileNameDisplay.textContent = name;
        selectedFileInfo.classList.remove('d-none');
        btnSelectFile.classList.add('d-none');
    }

    // --- 2. Fill Demo Domains ---
    if (btnFillDemoText && domainsText) {
        btnFillDemoText.addEventListener('click', () => {
            domainsText.value = [
                'google.com',
                'uol.com.br',
                'microsoft.com',
                'startup-fantastica-2026-xyz.com',
                'globo.com',
                'meu-negocio-disponivel-12345.com.br',
                'usp.br',
                'app-revolucionario-teste-8877.io',
                'github.com',
                'novo-site-livre-4567.com'
            ].join('\n');
            
            const textTabTrigger = document.querySelector('#text-tab');
            if (textTabTrigger) {
                bootstrap.Tab.getOrCreateInstance(textTabTrigger).show();
            }
        });
    }

    // --- 3. HTML Helpers for Rows ---
    function getRowBadgeHtml(data) {
        if (data.status === 'pending') {
            return `<span class="badge bg-light text-primary border">
                <span class="spinner-border spinner-border-sm me-1" style="width: 0.75rem; height: 0.75rem;"></span> Consultando...
            </span>`;
        }
        if (data.status === 'cancelled') {
            return `<span class="badge bg-secondary-subtle text-secondary border border-secondary-subtle px-2 py-1" title="Verificação interrompida antes da consulta">
                <i class="bi bi-dash-circle me-1"></i> Não Verificado
            </span>`;
        }
        if (data.status === 'available') {
            const isDns = data.status_label && data.status_label.includes('DNS');
            return `<span class="badge bg-success-subtle text-success border border-success-subtle px-2 py-1" title="${escapeHtml(data.details || '')}">
                <i class="bi bi-check-circle-fill me-1"></i> ${isDns ? 'Disponível (DNS)' : 'Disponível'}
            </span>`;
        }
        if (data.status === 'registered') {
            const isDns = data.status_label && data.status_label.includes('DNS');
            return `<span class="badge bg-danger-subtle text-danger border border-danger-subtle px-2 py-1" title="${escapeHtml(data.details || '')}">
                <i class="bi bi-x-circle-fill me-1"></i> ${isDns ? 'Registrado (DNS)' : 'Registrado'}
            </span>`;
        }
        if (data.status === 'rate_limited') {
            return `<span class="badge bg-warning-subtle text-dark border border-warning-subtle px-2 py-1" title="${escapeHtml(data.details || '')}">
                <i class="bi bi-shield-exclamation me-1 text-warning"></i> Limite Atingido
            </span>`;
        }
        return `<span class="badge bg-secondary-subtle text-secondary border border-secondary-subtle px-2 py-1" title="${escapeHtml(data.details || '')}">
            <i class="bi bi-exclamation-triangle-fill me-1"></i> ${escapeHtml(data.status_label || 'Indefinido')}
        </span>`;
    }

    function getRowOwnerHtml(data) {
        if (data.status === 'pending') {
            return '<span class="text-muted small"><span class="spinner-grow spinner-grow-sm me-1" style="width: 0.5rem; height: 0.5rem;"></span> Consultando WHOIS...</span>';
        }
        if (data.status === 'cancelled') {
            return '<span class="text-muted small">-</span>';
        }
        if (data.status === 'available') {
            return '<span class="text-success small fw-medium"><i class="bi bi-check2"></i> Livre para registro</span>';
        }
        if (data.is_redacted) {
            return '<span class="badge bg-light text-muted border fw-normal"><i class="bi bi-shield-lock me-1"></i> Protegido por Privacidade</span>';
        }
        if (data.owner && data.owner !== '-') {
            let html = `<div class="fw-medium text-dark">${escapeHtml(data.owner)}</div>`;
            if (data.owner_id) {
                html += `<div class="small text-muted font-monospace"><i class="bi bi-card-text me-1"></i>${escapeHtml(data.owner_id)}</div>`;
            }
            return html;
        }
        return '<span class="text-muted small">-</span>';
    }

    function getRowActionsHtml(data) {
        if (data.status === 'pending') {
            return `<button class="btn btn-sm btn-light border py-1 px-2 text-muted" disabled style="opacity: 0.6;">
                <i class="bi bi-hourglass-split"></i>
            </button>`;
        }
        if (data.status === 'cancelled') {
            return `
                <div class="d-flex justify-content-end gap-1">
                    <button class="btn btn-sm btn-light border py-1 px-2 btn-copy-domain" data-domain="${escapeHtml(data.domain)}" title="Copiar domínio">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
            `;
        }
        let html = `
            <div class="d-flex justify-content-end gap-1">
                <button type="button" class="btn btn-sm btn-outline-primary py-1 px-2 btn-view-details" data-domain="${escapeHtml(data.domain)}" title="Ver todos os detalhes do WHOIS">
                    <i class="bi bi-info-circle me-1"></i> Detalhes
                </button>
        `;
        if (data.status === 'available') {
            const regUrl = data.domain.endsWith('.br') 
                ? `https://registro.br/busca-dominio/?pesquisa=${encodeURIComponent(data.domain)}`
                : `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(data.domain)}`;
            html += `
                <a href="${regUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-success py-1 px-2" title="Registrar no provedor oficial">
                    <i class="bi bi-bag-plus"></i>
                </a>
            `;
        } else {
            html += `
                <button class="btn btn-sm btn-light border py-1 px-2 btn-copy-domain" data-domain="${escapeHtml(data.domain)}" title="Copiar domínio">
                    <i class="bi bi-clipboard"></i>
                </button>
            `;
        }
        html += '</div>';
        return html;
    }

    function updateRowInPlace(data) {
        const tr = resultsTableBody.querySelector(`tr[data-domain="${CSS.escape(data.domain.toLowerCase())}"]`);
        if (!tr) return;

        tr.className = `result-row status-${data.status}`;
        tr.dataset.status = data.status;

        // Atualiza apenas as células específicas diretamente sem recriar o elemento
        const tdStatus = tr.children[1];
        if (tdStatus) tdStatus.innerHTML = getRowBadgeHtml(data);

        const tdDomain = tr.children[2];
        if (tdDomain) {
            tdDomain.innerHTML = `
                <div class="fw-bold text-dark">${escapeHtml(data.domain)}</div>
                ${data.country && data.country !== '-' ? `<span class="badge bg-light text-secondary border font-monospace mt-1" style="font-size: 0.7rem;">${escapeHtml(data.country)}</span>` : ''}
            `;
        }

        const tdOwner = tr.children[3];
        if (tdOwner) tdOwner.innerHTML = getRowOwnerHtml(data);

        const tdRegistrar = tr.children[4];
        if (tdRegistrar) tdRegistrar.textContent = data.registrar || '-';

        const tdExp = tr.children[5];
        if (tdExp) tdExp.textContent = data.expiration_date || '-';

        const tdActions = tr.children[6];
        if (tdActions) {
            tdActions.innerHTML = getRowActionsHtml(data);
            bindRowActions(tdActions);
        }
    }

    function bindRowActions(container) {
        container.querySelectorAll('.btn-view-details').forEach(btn => {
            btn.addEventListener('click', () => {
                const domainName = btn.dataset.domain;
                const found = allResults.find(r => r.domain === domainName);
                if (found) openWhoisModal(found);
            });
        });

        container.querySelectorAll('.btn-copy-domain').forEach(btn => {
            btn.addEventListener('click', () => {
                copyToClipboard(btn.dataset.domain);
                showToast(`Domínio ${btn.dataset.domain} copiado!`, 'success');
            });
        });
    }

    // --- 4. Form Submission (Live Concurrent Check com In-Place Updates) ---
    if (domainForm) {
        domainForm.addEventListener('submit', async function (e) {
            e.preventDefault();

            const activeTab = document.querySelector('#inputTabs .nav-link.active');
            const isUploadTab = activeTab && activeTab.id === 'upload-tab';

            let formData = new FormData();

            if (isUploadTab) {
                if (!fileInput.files || fileInput.files.length === 0) {
                    showToast('Por favor, selecione um arquivo .txt ou .csv.', 'warning');
                    return;
                }
                formData.append('file', fileInput.files[0]);
            } else {
                const text = domainsText.value.trim();
                if (!text) {
                    showToast('Por favor, digite ou cole ao menos um domínio.', 'warning');
                    return;
                }
                formData.append('text', text);
            }

            btnSubmit.disabled = true;
            btnSubmit.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Lendo lista...';

            let domainList = [];
            try {
                const parseResponse = await fetch('/api/parse', {
                    method: 'POST',
                    body: formData
                });
                const parseData = await parseResponse.json();
                domainList = parseData.domains || [];
            } catch (err) {
                console.error(err);
                showToast('Erro ao ler a lista de domínios. Tente novamente.', 'danger');
                btnSubmit.disabled = false;
                btnSubmit.innerHTML = '<i class="bi bi-search me-1"></i> Verificar Domínios';
                return;
            }

            if (domainList.length === 0) {
                showToast('Nenhum domínio válido encontrado no arquivo ou texto.', 'warning');
                btnSubmit.disabled = false;
                btnSubmit.innerHTML = '<i class="bi bi-search me-1"></i> Verificar Domínios';
                return;
            }

            // Inicializa todos como "pending" (placeholders)
            allResults = domainList.map(domain => ({
                domain: domain,
                status: 'pending',
                status_label: 'Consultando...',
                status_class: 'info',
                owner: '-',
                owner_id: '',
                is_redacted: false,
                registrar: '...',
                registrar_url: '',
                creation_date: '...',
                expiration_date: '...',
                updated_date: '...',
                country: '-',
                emails: [],
                name_servers: [],
                status_epp: [],
                dnssec: '-',
                whois_server: '-',
                responsible_person: '-',
                details: 'Consulta em andamento...',
                raw_text: ''
            }));

            isCancelled = false;
            isScanning = true;
            currentPage = 1;
            sortColumn = null; // mantém a ordem natural durante o scan para não pular linhas
            
            // Recolhe o formulário grande e exibe a barra compacta com o botão "Adicionar / Nova Busca"
            if (inputCard) inputCard.classList.add('d-none');
            if (collapsedInputBar) {
                collapsedInputBar.classList.remove('d-none');
                if (collapsedDomainCount) collapsedDomainCount.textContent = domainList.length;
                if (collapsedSourceInfo) {
                    collapsedSourceInfo.textContent = isUploadTab 
                        ? (fileInput.files && fileInput.files[0] ? fileInput.files[0].name : 'Arquivo enviado')
                        : 'Lista digitada';
                }
            }

            // Prepara a seção de progresso
            if (progressHideTimer) clearTimeout(progressHideTimer);
            progressSection.classList.remove('d-none');
            progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-primary';
            progressBar.style.width = '0%';
            progressPercentage.className = 'badge bg-primary fs-6 px-3';
            progressPercentage.textContent = '0%';
            if (progressSpinner) progressSpinner.classList.remove('d-none');
            if (btnDismissProgress) btnDismissProgress.classList.add('d-none');
            if (btnCancelScan) {
                btnCancelScan.classList.remove('d-none');
                btnCancelScan.disabled = false;
            }

            statsSection.classList.remove('d-none');
            resultsSection.classList.remove('d-none');
            if (btnReset) btnReset.style.display = 'inline-block';

            updateProgressBar(0, domainList.length);
            updateFilterCountsAndStats();
            
            // Renderiza a tabela inicial com placeholders (apenas 1 render, SEM PISCAR)
            applyFilterAndRender();

            // Executa consultas concorrentes com controle de taxa inteligente
            const total = domainList.length;
            let completed = 0;
            const concurrency = 4;
            let index = 0;

            async function worker() {
                while (index < domainList.length) {
                    if (isCancelled) break;
                    const currentIndex = index++;
                    const domain = domainList[currentIndex];

                    try {
                        const res = await fetch('/api/check-single', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ domain: domain })
                        });
                        const data = await res.json();
                        
                        // Atualiza no array em memória
                        const targetIdx = allResults.findIndex(r => r.domain === domain);
                        if (targetIdx !== -1) {
                            allResults[targetIdx] = data;
                        }
                        
                        // Atualização cirúrgica in-place na linha do DOM (sem recriar a tabela)
                        updateRowInPlace(data);

                        // Se porventura receber rate limit, dá um respiro de 1s para não sobrecarregar
                        if (data.status === 'rate_limited') {
                            await new Promise(r => setTimeout(r, 1000));
                        }
                    } catch (err) {
                        const fallbackData = {
                            domain: domain,
                            status: 'error',
                            status_label: 'Erro na Consulta',
                            status_class: 'secondary',
                            owner: '-',
                            owner_id: '',
                            is_redacted: false,
                            registrar: '-',
                            registrar_url: '',
                            creation_date: '-',
                            expiration_date: '-',
                            updated_date: '-',
                            country: '-',
                            emails: [],
                            name_servers: [],
                            status_epp: [],
                            dnssec: '-',
                            whois_server: '-',
                            responsible_person: '-',
                            details: 'Erro de conexão na consulta.',
                            raw_text: ''
                        };
                        const targetIdx = allResults.findIndex(r => r.domain === domain);
                        if (targetIdx !== -1) {
                            allResults[targetIdx] = fallbackData;
                        }
                        updateRowInPlace(fallbackData);
                    }

                    completed++;
                    updateProgressBar(completed, total);
                    updateFilterCountsAndStats();
                }
            }

            const workers = [];
            for (let i = 0; i < Math.min(concurrency, total); i++) {
                workers.push(worker());
            }

            await Promise.all(workers);

            isScanning = false;
            btnSubmit.disabled = false;
            btnSubmit.innerHTML = '<i class="bi bi-search me-1"></i> Verificar Domínios';

            // Ao terminar, atualiza a paginação e contagens finais
            updatePaginationInfo();

            if (isCancelled) {
                if (progressSpinner) progressSpinner.classList.add('d-none');
                progressText.innerHTML = '<i class="bi bi-pause-circle text-warning fs-5 me-1"></i> Verificação interrompida pelo usuário.';
                progressDetail.textContent = `${completed} de ${total} domínios verificados.`;
                progressBar.className = 'progress-bar bg-warning';
                progressPercentage.className = 'badge bg-warning text-dark fs-6 px-3';
                if (btnCancelScan) btnCancelScan.classList.add('d-none');
                if (btnDismissProgress) btnDismissProgress.classList.remove('d-none');

                // Atualiza domínios não verificados restantes para evitar spinners infinitos
                allResults.forEach(r => {
                    if (r.status === 'pending') {
                        r.status = 'cancelled';
                        r.status_label = 'Não Verificado';
                        r.status_class = 'secondary';
                        r.details = 'Verificação interrompida pelo usuário antes da consulta.';
                        updateRowInPlace(r);
                    }
                });
                updateFilterCountsAndStats();

                // Esconde a notificação automaticamente após 3.5 segundos
                if (progressHideTimer) clearTimeout(progressHideTimer);
                progressHideTimer = setTimeout(() => {
                    progressSection.classList.add('d-none');
                }, 3500);
            } else {
                if (progressSpinner) progressSpinner.classList.add('d-none');
                progressText.innerHTML = '<i class="bi bi-check-circle text-success fs-5 me-1"></i> Verificação concluída com sucesso!';
                progressDetail.textContent = `Todos os ${total} domínios foram processados via WHOIS.`;
                progressBar.className = 'progress-bar bg-success';
                progressPercentage.className = 'badge bg-success fs-6 px-3';
                if (btnCancelScan) btnCancelScan.classList.add('d-none');
                if (btnDismissProgress) btnDismissProgress.classList.remove('d-none');

                if (progressHideTimer) clearTimeout(progressHideTimer);
                progressHideTimer = setTimeout(() => {
                    progressSection.classList.add('d-none');
                }, 3000);
            }
        });
    }

    if (btnCancelScan) {
        btnCancelScan.addEventListener('click', () => {
            isCancelled = true;
            btnCancelScan.classList.add('d-none');
            if (btnDismissProgress) btnDismissProgress.classList.remove('d-none');
            if (progressSpinner) progressSpinner.classList.add('d-none');
            progressText.innerHTML = '<i class="bi bi-pause-circle text-warning fs-5 me-1"></i> Verificação cancelada.';
            progressDetail.textContent = 'Interrompendo consultas e finalizando...';
            progressBar.className = 'progress-bar bg-warning';
            progressPercentage.className = 'badge bg-warning text-dark fs-6 px-3';

            // Esconde a notificação automaticamente após 2.5 segundos
            if (progressHideTimer) clearTimeout(progressHideTimer);
            progressHideTimer = setTimeout(() => {
                progressSection.classList.add('d-none');
            }, 2500);
        });
    }

    if (btnDismissProgress) {
        btnDismissProgress.addEventListener('click', () => {
            if (progressHideTimer) clearTimeout(progressHideTimer);
            progressSection.classList.add('d-none');
        });
    }

    if (btnShowInputCard) {
        btnShowInputCard.addEventListener('click', () => {
            if (collapsedInputBar) collapsedInputBar.classList.add('d-none');
            if (inputCard) {
                inputCard.classList.remove('d-none');
                if (inputCardHeader) inputCardHeader.classList.remove('d-none');
                inputCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    }

    if (btnHideInputCard) {
        btnHideInputCard.addEventListener('click', () => {
            if (inputCard) inputCard.classList.add('d-none');
            if (collapsedInputBar) collapsedInputBar.classList.remove('d-none');
        });
    }

    if (btnReset) {
        btnReset.addEventListener('click', () => {
            allResults = [];
            filteredResults = [];
            resultsTableBody.innerHTML = '';
            statsSection.classList.add('d-none');
            resultsSection.classList.add('d-none');
            progressSection.classList.add('d-none');
            if (progressHideTimer) clearTimeout(progressHideTimer);
            if (collapsedInputBar) collapsedInputBar.classList.add('d-none');
            if (inputCard) {
                inputCard.classList.remove('d-none');
                if (inputCardHeader) inputCardHeader.classList.add('d-none');
            }
            btnReset.style.display = 'none';
            if (domainsText) domainsText.value = '';
            if (fileInput) fileInput.value = '';
            if (selectedFileInfo) selectedFileInfo.classList.add('d-none');
            if (btnSelectFile) btnSelectFile.classList.remove('d-none');
        });
    }

    function updateProgressBar(completed, total) {
        const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
        progressBar.style.width = `${pct}%`;
        progressPercentage.textContent = `${pct}%`;
        progressText.textContent = `Consultando WHOIS... (${completed} de ${total})`;
        progressDetail.textContent = `Analisando registros oficiais, titulares e DNS...`;
    }

    function updateFilterCountsAndStats() {
        const total = allResults.length;
        const available = allResults.filter(r => r.status === 'available').length;
        const registered = allResults.filter(r => r.status === 'registered').length;
        const errors = allResults.filter(r => r.status === 'error' || r.status === 'invalid').length;

        statTotal.textContent = total;
        statAvailable.textContent = available;
        statRegistered.textContent = registered;
        statErrors.textContent = errors;

        filterCountAll.textContent = total;
        filterCountAvailable.textContent = available;
        filterCountRegistered.textContent = registered;
    }

    // --- 5. Filtering, Sorting & Pagination (Chamado apenas pelo usuário) ---

    // Filter Buttons
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            currentPage = 1;
            applyFilterAndRender();
        });
    });

    // Search Box
    if (searchFilter) {
        searchFilter.addEventListener('input', () => {
            searchQuery = searchFilter.value.trim().toLowerCase();
            currentPage = 1;
            applyFilterAndRender();
        });
    }

    // Page Size Selector
    if (pageSizeSelect) {
        pageSizeSelect.addEventListener('change', () => {
            const val = pageSizeSelect.value;
            pageSize = val === 'all' ? Infinity : parseInt(val, 10);
            currentPage = 1;
            applyFilterAndRender();
        });
    }

    // Column Sorting
    document.querySelectorAll('.sortable-th').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.dataset.sort;
            if (sortColumn === col) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = col;
                sortDirection = 'asc';
            }
            updateSortIcons();
            applyFilterAndRender();
        });
    });

    function updateSortIcons() {
        document.querySelectorAll('.sortable-th').forEach(th => {
            const icon = th.querySelector('.sort-icon');
            if (!icon) return;
            if (th.dataset.sort === sortColumn) {
                icon.className = sortDirection === 'asc' 
                    ? 'bi bi-sort-down text-primary small ms-1 sort-icon' 
                    : 'bi bi-sort-up text-primary small ms-1 sort-icon';
            } else {
                icon.className = 'bi bi-arrow-down-up text-muted small ms-1 sort-icon';
            }
        });
    }

    function parseDateForSort(dateStr) {
        if (!dateStr || dateStr === '-' || dateStr === '...') return 0;
        const parts = dateStr.split('/');
        if (parts.length === 3) {
            return new Date(parts[2], parts[1] - 1, parts[0]).getTime();
        }
        return new Date(dateStr).getTime() || 0;
    }

    function applyFilterAndRender() {
        filteredResults = allResults.filter(item => {
            if (currentFilter !== 'all' && item.status !== currentFilter) {
                return false;
            }
            if (searchQuery) {
                const matchDomain = item.domain && item.domain.toLowerCase().includes(searchQuery);
                const matchOwner = item.owner && item.owner.toLowerCase().includes(searchQuery);
                const matchOwnerId = item.owner_id && item.owner_id.toLowerCase().includes(searchQuery);
                const matchRegistrar = item.registrar && item.registrar.toLowerCase().includes(searchQuery);
                if (!matchDomain && !matchOwner && !matchOwnerId && !matchRegistrar) {
                    return false;
                }
            }
            return true;
        });

        // Ordenação (se uma coluna tiver sido selecionada)
        if (sortColumn) {
            const statusOrder = { 'available': 0, 'registered': 1, 'invalid': 2, 'error': 3, 'pending': 4 };
            filteredResults.sort((a, b) => {
                let res = 0;
                if (sortColumn === 'status') {
                    const orderA = statusOrder[a.status] ?? 5;
                    const orderB = statusOrder[b.status] ?? 5;
                    res = orderA - orderB;
                } else if (sortColumn === 'domain') {
                    res = (a.domain || '').localeCompare(b.domain || '');
                } else if (sortColumn === 'owner') {
                    res = (a.owner || '').localeCompare(b.owner || '');
                } else if (sortColumn === 'registrar') {
                    res = (a.registrar || '').localeCompare(b.registrar || '');
                } else if (sortColumn === 'expiration_date') {
                    const dateA = parseDateForSort(a.expiration_date);
                    const dateB = parseDateForSort(b.expiration_date);
                    res = dateA - dateB;
                }
                return sortDirection === 'asc' ? res : -res;
            });
        }

        renderTable();
        renderPagination();
    }

    function renderTable() {
        resultsTableBody.innerHTML = '';

        if (filteredResults.length === 0) {
            noResultsFiltered.classList.remove('d-none');
            return;
        } else {
            noResultsFiltered.classList.add('d-none');
        }

        const total = filteredResults.length;
        const totalPages = pageSize === Infinity ? 1 : Math.ceil(total / pageSize);
        if (currentPage > totalPages) currentPage = totalPages || 1;

        const startIndex = (currentPage - 1) * pageSize;
        const endIndex = pageSize === Infinity ? total : Math.min(startIndex + pageSize, total);
        const pageItems = filteredResults.slice(startIndex, endIndex);

        const fragment = document.createDocumentFragment();

        pageItems.forEach((data, index) => {
            const rowIndex = startIndex + index + 1;
            const tr = document.createElement('tr');
            tr.className = `result-row status-${data.status}`;
            tr.dataset.domain = data.domain.toLowerCase();
            tr.dataset.status = data.status;

            tr.innerHTML = `
                <td class="text-center text-muted small">${rowIndex}</td>
                <td>${getRowBadgeHtml(data)}</td>
                <td>
                    <div class="fw-bold text-dark">${escapeHtml(data.domain)}</div>
                    ${data.country && data.country !== '-' ? `<span class="badge bg-light text-secondary border font-monospace mt-1" style="font-size: 0.7rem;">${escapeHtml(data.country)}</span>` : ''}
                </td>
                <td>${getRowOwnerHtml(data)}</td>
                <td class="text-secondary small">${escapeHtml(data.registrar || '-')}</td>
                <td class="text-secondary small font-monospace">${escapeHtml(data.expiration_date || '-')}</td>
                <td class="text-end">${getRowActionsHtml(data)}</td>
            `;

            fragment.appendChild(tr);
        });

        resultsTableBody.appendChild(fragment);

        // Bind events on buttons inside table
        bindRowActions(resultsTableBody);
    }

    function updatePaginationInfo() {
        const total = filteredResults.length;
        if (total === 0) {
            paginationInfo.textContent = 'Nenhum domínio a exibir';
            paginationContainer.innerHTML = '';
            return;
        }
        const startIndex = (currentPage - 1) * pageSize + 1;
        const endIndex = pageSize === Infinity ? total : Math.min(currentPage * pageSize, total);
        paginationInfo.innerHTML = `Exibindo <strong>${startIndex}</strong> a <strong>${endIndex}</strong> de <strong>${total}</strong> domínios ${allResults.length > total ? `(filtrados de ${allResults.length})` : ''}`;
    }

    function renderPagination() {
        const total = filteredResults.length;
        updatePaginationInfo();

        if (total === 0) {
            paginationContainer.innerHTML = '';
            return;
        }

        const totalPages = pageSize === Infinity ? 1 : Math.ceil(total / pageSize);
        if (totalPages <= 1) {
            paginationContainer.innerHTML = '';
            return;
        }

        let html = '';

        html += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <button class="page-link" data-page="1" title="Primeira Página">&laquo;&laquo;</button>
        </li>`;

        html += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <button class="page-link" data-page="${currentPage - 1}" title="Página Anterior">&laquo;</button>
        </li>`;

        let startPage = Math.max(1, currentPage - 2);
        let endPage = Math.min(totalPages, currentPage + 2);

        if (startPage > 1) {
            html += `<li class="page-item"><button class="page-link" data-page="1">1</button></li>`;
            if (startPage > 2) {
                html += `<li class="page-item disabled"><span class="page-link border-0">...</span></li>`;
            }
        }

        for (let p = startPage; p <= endPage; p++) {
            html += `<li class="page-item ${p === currentPage ? 'active' : ''}">
                <button class="page-link" data-page="${p}">${p}</button>
            </li>`;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                html += `<li class="page-item disabled"><span class="page-link border-0">...</span></li>`;
            }
            html += `<li class="page-item"><button class="page-link" data-page="${totalPages}">${totalPages}</button></li>`;
        }

        html += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <button class="page-link" data-page="${currentPage + 1}" title="Próxima Página">&raquo;</button>
        </li>`;

        html += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <button class="page-link" data-page="${totalPages}" title="Última Página">&raquo;&raquo;</button>
        </li>`;

        paginationContainer.innerHTML = html;

        paginationContainer.querySelectorAll('button.page-link').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetPage = parseInt(btn.dataset.page, 10);
                if (targetPage && targetPage !== currentPage && targetPage >= 1 && targetPage <= totalPages) {
                    currentPage = targetPage;
                    renderTable();
                    renderPagination();
                    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    }

    // --- 6. Modal de Detalhes Completos do WHOIS ---
    function openWhoisModal(item) {
        if (!whoisModal) return;
        activeModalDomain = item.domain;

        document.getElementById('modalDomainName').textContent = item.domain;
        
        const badgeEl = document.getElementById('modalDomainBadge');
        if (item.status === 'available') {
            badgeEl.className = 'badge bg-success fs-6';
            badgeEl.textContent = 'Disponível';
        } else if (item.status === 'registered') {
            badgeEl.className = 'badge bg-danger fs-6';
            badgeEl.textContent = 'Registrado';
        } else if (item.status === 'rate_limited') {
            badgeEl.className = 'badge bg-warning text-dark fs-6';
            badgeEl.textContent = 'Limite Atingido (Registro.br)';
        } else {
            badgeEl.className = 'badge bg-secondary fs-6';
            badgeEl.textContent = item.status_label || 'Indefinido';
        }

        document.getElementById('modalOwnerName').textContent = item.owner && item.owner !== '-' ? item.owner : 'Não especificado ou protegido';
        const modalOwnerId = document.getElementById('modalOwnerId');
        if (item.owner_id) {
            modalOwnerId.textContent = item.owner_id;
            modalOwnerId.style.display = 'inline-block';
        } else {
            modalOwnerId.style.display = 'none';
        }

        document.getElementById('modalPerson').textContent = item.responsible_person || '-';

        const emailsEl = document.getElementById('modalEmails');
        if (item.emails && item.emails.length > 0) {
            emailsEl.innerHTML = item.emails.map(e => `<div><i class="bi bi-envelope me-1"></i>${escapeHtml(e)}</div>`).join('');
        } else {
            emailsEl.textContent = 'Não informado / Oculto por privacidade';
        }

        const locParts = [item.city, item.state, item.country].filter(p => p && p !== '-');
        document.getElementById('modalLocation').textContent = locParts.length > 0 ? locParts.join(', ') : '-';

        document.getElementById('modalRegistrar').textContent = item.registrar || '-';
        const regUrlEl = document.getElementById('modalRegistrarUrl');
        if (item.registrar_url) {
            regUrlEl.href = item.registrar_url.startsWith('http') ? item.registrar_url : `https://${item.registrar_url}`;
            regUrlEl.style.display = 'inline-block';
        } else {
            regUrlEl.style.display = 'none';
        }

        document.getElementById('modalWhoisServer').textContent = item.whois_server || '-';

        const nsContainer = document.getElementById('modalNameServers');
        if (item.name_servers && item.name_servers.length > 0) {
            nsContainer.innerHTML = item.name_servers.map(ns => 
                `<span class="badge bg-light text-dark border font-monospace px-2 py-1"><i class="bi bi-hdd-rack me-1 text-primary"></i>${escapeHtml(ns)}</span>`
            ).join(' ');
        } else {
            nsContainer.innerHTML = '<span class="badge bg-light text-muted border">Nenhum servidor DNS listado</span>';
        }

        document.getElementById('modalDnssec').textContent = item.dnssec || 'Não assinado';
        const eppContainer = document.getElementById('modalStatusEpp');
        if (item.status_epp && item.status_epp.length > 0) {
            eppContainer.innerHTML = item.status_epp.map(st => 
                `<span class="badge bg-light text-secondary border font-monospace" style="font-size: 0.72rem;">${escapeHtml(st)}</span>`
            ).join(' ');
        } else {
            eppContainer.innerHTML = '<span class="badge bg-light text-muted border">-</span>';
        }

        document.getElementById('modalCreationDate').textContent = item.creation_date || '-';
        document.getElementById('modalUpdatedDate').textContent = item.updated_date || '-';
        document.getElementById('modalExpirationDate').textContent = item.expiration_date || '-';

        const rawTextEl = document.getElementById('modalRawText');
        rawTextEl.textContent = item.raw_text || 'Dados brutos não disponíveis para este domínio.';

        const btnModalRegister = document.getElementById('btnModalRegister');
        if (item.status === 'available') {
            const regUrl = item.domain.endsWith('.br') 
                ? `https://registro.br/busca-dominio/?pesquisa=${encodeURIComponent(item.domain)}`
                : `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(item.domain)}`;
            btnModalRegister.href = regUrl;
            btnModalRegister.style.display = 'inline-block';
        } else {
            btnModalRegister.style.display = 'none';
        }

        whoisModal.show();
    }

    const btnCopyModalDomain = document.getElementById('btnCopyModalDomain');
    if (btnCopyModalDomain) {
        btnCopyModalDomain.addEventListener('click', () => {
            if (activeModalDomain) {
                copyToClipboard(activeModalDomain);
                showToast(`Domínio ${activeModalDomain} copiado!`, 'success');
            }
        });
    }

    // --- 7. Exportação e Cópia ---
    if (btnExportAllCsv) {
        btnExportAllCsv.addEventListener('click', () => {
            exportCsv(allResults, 'all');
        });
    }

    if (btnExportAvailableCsv) {
        btnExportAvailableCsv.addEventListener('click', () => {
            exportCsv(allResults, 'available');
        });
    }

    if (btnCopyAvailable) {
        btnCopyAvailable.addEventListener('click', () => {
            const availableList = allResults
                .filter(r => r.status === 'available')
                .map(r => r.domain);

            if (availableList.length === 0) {
                showToast('Nenhum domínio disponível para copiar.', 'warning');
                return;
            }

            copyToClipboard(availableList.join('\n'));
            showToast(`${availableList.length} domínios disponíveis copiados com sucesso!`, 'success');
        });
    }

    async function exportCsv(results, filter) {
        if (!results || results.length === 0) {
            showToast('Nenhum resultado para exportar.', 'warning');
            return;
        }

        try {
            const response = await fetch('/api/export-csv', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ results: results, filter: filter })
            });

            if (!response.ok) throw new Error('Falha ao exportar');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filter === 'available' ? 'dominios_disponiveis.csv' : 'relatorio_completo_whois.csv';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } catch (err) {
            console.error(err);
            showToast('Erro ao baixar arquivo CSV.', 'danger');
        }
    }

    function copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).catch(() => {
                fallbackCopy(text);
            });
        } else {
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
        } catch (e) {
            console.warn(e);
        }
        document.body.removeChild(textarea);
    }

    function showToast(message, type) {
        if (!toast || !toastMessage) return;
        toastMessage.innerHTML = message;
        toast.show();
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // --- 8. Inicializa com dados pré-carregados pelo servidor ---
    if (window.SERVER_PRELOADED_RESULTS && Array.isArray(window.SERVER_PRELOADED_RESULTS) && window.SERVER_PRELOADED_RESULTS.length > 0) {
        allResults = window.SERVER_PRELOADED_RESULTS;
        updateFilterCountsAndStats();
        applyFilterAndRender();
        if (btnReset) btnReset.style.display = 'inline-block';
    }
});
