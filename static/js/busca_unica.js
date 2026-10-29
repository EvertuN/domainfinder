// DomainFinder - Lógica da Busca Única Multi-Extensões
// Mantém exatamente o mesmo padrão e comportamento elegante da Busca em Lote

document.addEventListener('DOMContentLoaded', function () {
    // DOM Elements - Input
    const singleDomainForm = document.getElementById('singleDomainForm');
    const domainKeyword = document.getElementById('domainKeyword');
    const btnSubmit = document.getElementById('btnSubmit');
    const btnReset = document.getElementById('btnReset');
    const demoButtons = document.querySelectorAll('.btn-demo-kw');

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

    // Modal WHOIS
    const whoisModalEl = document.getElementById('whoisDetailModal');
    const whoisModal = whoisModalEl ? new bootstrap.Modal(whoisModalEl) : null;
    let activeModalDomain = null;

    // State
    let tldList = [];
    let allResults = [];
    let filteredResults = [];
    let currentFilter = 'all';
    let searchQuery = '';
    let currentPage = 1;
    let pageSize = 50;
    let sortColumn = null;
    let sortDirection = 'asc';
    let isCancelled = false;
    let isScanning = false;
    let currentKeyword = '';

    // --- 1. Carregamento de TLDs ---
    async function loadTlds() {
        try {
            const res = await fetch('/api/tlds');
            if (res.ok) {
                tldList = await res.json();
            } else {
                throw new Error('Falha ao carregar TLDs');
            }
        } catch (e) {
            console.warn('Usando lista local de TLDs:', e);
            tldList = getFallbackTldList();
        }
    }

    function getFallbackTldList() {
        return [
            { tld: '.com', name: 'Comercial Global', category_name: 'Mais Populares' },
            { tld: '.com.br', name: 'Brasil Oficial', category_name: 'Mais Populares' },
            { tld: '.net', name: 'Redes & Infra', category_name: 'Mais Populares' },
            { tld: '.org', name: 'Organizações', category_name: 'Mais Populares' },
            { tld: '.io', name: 'Tech & Startups', category_name: 'Mais Populares' },
            { tld: '.ai', name: 'Inteligência Artificial (IA)', category_name: 'Mais Populares' },
            { tld: '.co', name: 'Companhias Globais', category_name: 'Mais Populares' },
            { tld: '.dev', name: 'Desenvolvedores', category_name: 'Mais Populares' },
            { tld: '.app', name: 'Aplicativos', category_name: 'Mais Populares' },
            { tld: '.me', name: 'Marca Pessoal', category_name: 'Mais Populares' },
            { tld: '.net.br', name: 'Redes & Infra BR', category_name: 'Brasil (.br)' },
            { tld: '.org.br', name: 'Organizações BR', category_name: 'Brasil (.br)' },
            { tld: '.dev.br', name: 'Desenvolvedores BR', category_name: 'Brasil (.br)' },
            { tld: '.app.br', name: 'Aplicativos BR', category_name: 'Brasil (.br)' },
            { tld: '.tech.br', name: 'Tecnologia BR', category_name: 'Brasil (.br)' },
            { tld: '.io.br', name: 'Tech & Inovação BR', category_name: 'Brasil (.br)' },
            { tld: '.eco.br', name: 'Sustentabilidade BR', category_name: 'Brasil (.br)' },
            { tld: '.art.br', name: 'Artes & Cultura BR', category_name: 'Brasil (.br)' },
            { tld: '.store.br', name: 'Lojas Virtuais BR', category_name: 'Brasil (.br)' },
            { tld: '.site.br', name: 'Websites BR', category_name: 'Brasil (.br)' },
            { tld: '.blog.br', name: 'Blogs BR', category_name: 'Brasil (.br)' },
            { tld: '.eti.br', name: 'Especialistas TI BR', category_name: 'Brasil (.br)' },
            { tld: '.tech', name: 'Tecnologia', category_name: 'Tecnologia & IA' },
            { tld: '.cloud', name: 'Nuvem', category_name: 'Tecnologia & IA' },
            { tld: '.software', name: 'Software', category_name: 'Tecnologia & IA' },
            { tld: '.digital', name: 'Digital', category_name: 'Tecnologia & IA' },
            { tld: '.space', name: 'Space Tech', category_name: 'Tecnologia & IA' },
            { tld: '.global', name: 'Global', category_name: 'Tecnologia & IA' },
            { tld: '.ia', name: 'Inteligência Artificial', category_name: 'Tecnologia & IA' },
            { tld: '.uk', name: 'Reino Unido', category_name: 'Internacionais & Países' },
            { tld: '.co.uk', name: 'Empresas Reino Unido', category_name: 'Internacionais & Países' },
            { tld: '.pt', name: 'Portugal', category_name: 'Internacionais & Países' },
            { tld: '.es', name: 'Espanha', category_name: 'Internacionais & Países' },
            { tld: '.de', name: 'Alemanha', category_name: 'Internacionais & Países' },
            { tld: '.fr', name: 'França', category_name: 'Internacionais & Países' },
            { tld: '.it', name: 'Itália', category_name: 'Internacionais & Países' },
            { tld: '.nl', name: 'Holanda', category_name: 'Internacionais & Países' },
            { tld: '.eu', name: 'União Europeia', category_name: 'Internacionais & Países' },
            { tld: '.us', name: 'Estados Unidos', category_name: 'Internacionais & Países' },
            { tld: '.ca', name: 'Canadá', category_name: 'Internacionais & Países' },
            { tld: '.ch', name: 'Suíça', category_name: 'Internacionais & Países' },
            { tld: '.lat', name: 'América Latina', category_name: 'Internacionais & Países' },
            { tld: '.store', name: 'Lojas Virtuais', category_name: 'Negócios & Vendas' },
            { tld: '.shop', name: 'Shopping', category_name: 'Negócios & Vendas' },
            { tld: '.online', name: 'Online', category_name: 'Negócios & Vendas' },
            { tld: '.site', name: 'Site', category_name: 'Negócios & Vendas' },
            { tld: '.club', name: 'Club', category_name: 'Negócios & Vendas' },
            { tld: '.top', name: 'Top', category_name: 'Negócios & Vendas' },
            { tld: '.pro', name: 'Profissionais', category_name: 'Negócios & Vendas' },
            { tld: '.biz', name: 'Negócios', category_name: 'Negócios & Vendas' },
            { tld: '.agency', name: 'Agências', category_name: 'Negócios & Vendas' },
            { tld: '.solutions', name: 'Soluções', category_name: 'Negócios & Vendas' },
            { tld: '.link', name: 'Links', category_name: 'Negócios & Vendas' },
            { tld: '.live', name: 'Ao Vivo', category_name: 'Negócios & Vendas' },
            { tld: '.xyz', name: 'Web3 & Criativos', category_name: 'Negócios & Vendas' }
        ];
    }

    // --- 2. Sanitização da Palavra-Chave ---
    function sanitizeKeyword(raw) {
        if (!raw) return '';
        let s = raw.trim().toLowerCase();

        if (s.includes('://')) {
            s = s.split('://')[1] || '';
        }
        if (s.startsWith('www.')) {
            s = s.substring(4);
        }
        s = s.split('/')[0].split('?')[0].split('#')[0].split(':')[0];

        // Se o usuário digitou com uma extensão existente, extrai o nome base
        if (s.includes('.')) {
            const parts = s.split('.');
            if (parts.length > 0 && parts[0].length > 0) {
                s = parts[0];
            }
        }

        s = s.replace(/[^a-z0-9-]/g, '');
        s = s.replace(/^-+|-+$/g, '');
        return s;
    }

    // --- 3. Submissão e Execução da Busca ---
    if (singleDomainForm) {
        singleDomainForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            const rawKw = domainKeyword.value;
            const kw = sanitizeKeyword(rawKw);

            if (!kw) {
                domainKeyword.focus();
                showToast('Informe um nome de domínio válido.', 'warning');
                return;
            }

            currentKeyword = kw;
            domainKeyword.value = kw;

            if (tldList.length === 0) {
                await loadTlds();
            }

            startScan(kw);
        });
    }

    // Botões de demonstração rápida
    demoButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const kw = btn.dataset.kw;
            domainKeyword.value = kw;
            currentKeyword = kw;
            startScan(kw);
        });
    });

    async function startScan(kw) {
        if (isScanning) return;
        isScanning = true;
        isCancelled = false;

        // Reset UI
        allResults = [];
        filteredResults = [];
        resultsTableBody.innerHTML = '';
        currentPage = 1;
        currentFilter = 'all';
        searchQuery = '';
        if (searchFilter) searchFilter.value = '';

        filterButtons.forEach(b => {
            b.classList.remove('active');
            if (b.dataset.filter === 'all') b.classList.add('active');
        });

        // Monta a lista inicial de domínios com status 'pending'
        const domains = tldList.map(item => {
            const domain = `${kw}${item.tld}`;
            return {
                domain: domain,
                tld: item.tld,
                category: item.category_name,
                status: 'pending',
                status_label: 'Consultando...',
                status_class: 'secondary',
                owner: '-',
                owner_id: '',
                is_redacted: false,
                registrar: '-',
                registrar_url: '',
                creation_date: '-',
                expiration_date: '-',
                updated_date: '-',
                country: domain.endsWith('.br') ? 'BR' : '-',
                emails: [],
                name_servers: [],
                status_epp: [],
                dnssec: '-',
                whois_server: '-',
                responsible_person: '-',
                details: 'Aguardando verificação...',
                raw_text: ''
            };
        });

        allResults = domains;

        // Exibe seções e atualiza contadores
        if (btnReset) btnReset.style.display = 'inline-block';
        statsSection.classList.remove('d-none');
        resultsSection.classList.remove('d-none');
        progressSection.classList.remove('d-none');
        if (btnCancelScan) btnCancelScan.classList.remove('d-none');
        if (btnDismissProgress) btnDismissProgress.classList.add('d-none');
        if (progressSpinner) progressSpinner.classList.remove('d-none');

        updateFilterCountsAndStats();
        applyFilterAndRender();

        btnSubmit.disabled = true;
        btnSubmit.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Verificando...';

        const total = domains.length;
        let completed = 0;
        updateProgressBar(0, total);

        // Fila concorrente com 5 workers paralelos
        const concurrency = 5;
        let nextIndex = 0;

        async function worker() {
            while (nextIndex < domains.length) {
                if (isCancelled) break;
                const idx = nextIndex++;
                const item = domains[idx];

                try {
                    const res = await fetch('/api/check-single', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: item.domain })
                    });
                    const data = await res.json();

                    // Mescla mantendo os campos tld e category
                    const merged = {
                        ...data,
                        tld: item.tld,
                        category: item.category
                    };

                    const targetIdx = allResults.findIndex(r => r.domain === item.domain);
                    if (targetIdx !== -1) {
                        allResults[targetIdx] = merged;
                    }

                    updateRowInPlace(merged);
                } catch (err) {
                    const errorData = {
                        domain: item.domain,
                        tld: item.tld,
                        category: item.category,
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
                    const targetIdx = allResults.findIndex(r => r.domain === item.domain);
                    if (targetIdx !== -1) {
                        allResults[targetIdx] = errorData;
                    }
                    updateRowInPlace(errorData);
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
        btnSubmit.innerHTML = '<i class="bi bi-search me-1"></i> Verificar Disponibilidade';

        updatePaginationInfo();

        if (isCancelled) {
            if (progressSpinner) progressSpinner.classList.add('d-none');
            progressText.innerHTML = '<i class="bi bi-pause-circle text-warning fs-5 me-1"></i> Verificação interrompida pelo usuário.';
            progressDetail.textContent = `${completed} de ${total} extensões verificadas.`;
            progressBar.className = 'progress-bar bg-warning';
            progressPercentage.className = 'badge bg-warning text-dark fs-6 px-3';
            if (btnCancelScan) btnCancelScan.classList.add('d-none');
            if (btnDismissProgress) btnDismissProgress.classList.remove('d-none');

            allResults.forEach(r => {
                if (r.status === 'pending') {
                    r.status = 'cancelled';
                    r.status_label = 'Não Verificado';
                    r.status_class = 'secondary';
                    updateRowInPlace(r);
                }
            });
            updateFilterCountsAndStats();
        } else {
            if (progressSpinner) progressSpinner.classList.add('d-none');
            progressText.innerHTML = '<i class="bi bi-check-circle text-success fs-5 me-1"></i> Verificação concluída com sucesso!';
            progressDetail.textContent = `Todas as ${total} extensões foram consultadas.`;
            progressBar.className = 'progress-bar bg-success';
            progressPercentage.className = 'badge bg-success fs-6 px-3';
            if (btnCancelScan) btnCancelScan.classList.add('d-none');
            if (btnDismissProgress) btnDismissProgress.classList.remove('d-none');

            if (progressHideTimer) clearTimeout(progressHideTimer);
            progressHideTimer = setTimeout(() => {
                progressSection.classList.add('d-none');
            }, 3000);
        }
    }

    // --- 4. Cancelar e Limpar ---
    if (btnCancelScan) {
        btnCancelScan.addEventListener('click', () => {
            isCancelled = true;
            btnCancelScan.disabled = true;
            btnCancelScan.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Parando...';
        });
    }

    if (btnDismissProgress) {
        btnDismissProgress.addEventListener('click', () => {
            if (progressHideTimer) clearTimeout(progressHideTimer);
            progressSection.classList.add('d-none');
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
            btnReset.style.display = 'none';
            if (domainKeyword) domainKeyword.value = '';
            currentKeyword = '';
        });
    }

    function updateProgressBar(completed, total) {
        const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
        progressBar.style.width = `${pct}%`;
        progressPercentage.textContent = `${pct}%`;
        progressText.textContent = `Consultando WHOIS... (${completed} de ${total})`;
        progressDetail.textContent = `Analisando registros oficiais e disponibilidade...`;
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

    // --- 5. Filtragem, Ordenação e Paginação ---
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            currentPage = 1;
            applyFilterAndRender();
        });
    });

    if (searchFilter) {
        searchFilter.addEventListener('input', () => {
            searchQuery = searchFilter.value.trim().toLowerCase();
            currentPage = 1;
            applyFilterAndRender();
        });
    }

    if (pageSizeSelect) {
        pageSizeSelect.addEventListener('change', () => {
            const val = pageSizeSelect.value;
            pageSize = val === 'all' ? Infinity : parseInt(val, 10);
            currentPage = 1;
            applyFilterAndRender();
        });
    }

    // Ordenação por cabeçalho
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

    function applyFilterAndRender() {
        filteredResults = allResults.filter(item => {
            if (currentFilter !== 'all' && item.status !== currentFilter) {
                return false;
            }
            if (searchQuery) {
                const matchDomain = item.domain && item.domain.toLowerCase().includes(searchQuery);
                const matchTld = item.tld && item.tld.toLowerCase().includes(searchQuery);
                const matchCategory = item.category && item.category.toLowerCase().includes(searchQuery);
                const matchRegistrar = item.registrar && item.registrar.toLowerCase().includes(searchQuery);
                if (!matchDomain && !matchTld && !matchCategory && !matchRegistrar) {
                    return false;
                }
            }
            return true;
        });

        if (sortColumn) {
            const statusOrder = { 'available': 0, 'registered': 1, 'invalid': 2, 'error': 3, 'pending': 4 };
            filteredResults.sort((a, b) => {
                let res = 0;
                if (sortColumn === 'status') {
                    res = (statusOrder[a.status] ?? 5) - (statusOrder[b.status] ?? 5);
                } else if (sortColumn === 'domain') {
                    res = (a.domain || '').localeCompare(b.domain || '');
                } else if (sortColumn === 'tld') {
                    res = (a.tld || '').localeCompare(b.tld || '');
                } else if (sortColumn === 'category') {
                    res = (a.category || '').localeCompare(b.category || '');
                } else if (sortColumn === 'registrar') {
                    res = (a.registrar || '').localeCompare(b.registrar || '');
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
                    <div class="fw-bold font-monospace text-dark">${escapeHtml(data.domain)}</div>
                </td>
                <td><span class="badge bg-light text-dark border font-monospace">${escapeHtml(data.tld || '')}</span></td>
                <td><span class="small text-secondary">${escapeHtml(data.category || '-')}</span></td>
                <td class="text-secondary small">${escapeHtml(data.registrar || '-')}</td>
                <td class="text-end">${getRowActionsHtml(data)}</td>
            `;

            fragment.appendChild(tr);
        });

        resultsTableBody.appendChild(fragment);
        bindRowActions(resultsTableBody);
    }

    function getRowBadgeHtml(data) {
        if (data.status === 'pending') {
            return `<span class="badge bg-light text-primary border">
                <span class="spinner-border spinner-border-sm me-1" style="width: 0.75rem; height: 0.75rem;"></span> Consultando...
            </span>`;
        }
        if (data.status === 'cancelled') {
            return `<span class="badge bg-secondary-subtle text-secondary border border-secondary-subtle px-2 py-1">
                <i class="bi bi-dash-circle me-1"></i> Não Verificado
            </span>`;
        }
        if (data.status === 'available') {
            return `<span class="badge bg-success-subtle text-success border border-success-subtle px-2 py-1" title="${escapeHtml(data.details || '')}">
                <i class="bi bi-check-circle-fill me-1"></i> Disponível
            </span>`;
        }
        if (data.status === 'registered') {
            return `<span class="badge bg-danger-subtle text-danger border border-danger-subtle px-2 py-1" title="${escapeHtml(data.details || '')}">
                <i class="bi bi-x-circle-fill me-1"></i> Registrado
            </span>`;
        }
        if (data.status === 'rate_limited') {
            return `<span class="badge bg-warning-subtle text-dark border border-warning-subtle px-2 py-1">
                <i class="bi bi-shield-exclamation me-1 text-warning"></i> Limite Atingido
            </span>`;
        }
        if (data.status === 'invalid') {
            return `<span class="badge bg-warning-subtle text-dark border border-warning-subtle px-2 py-1">
                <i class="bi bi-exclamation-triangle me-1 text-warning"></i> ${escapeHtml(data.status_label || 'Inválido')}
            </span>`;
        }
        return `<span class="badge bg-secondary-subtle text-secondary border px-2 py-1">
            ${escapeHtml(data.status_label || 'Indefinido')}
        </span>`;
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

        let html = '<div class="d-flex justify-content-end gap-1">';

        if (data.status === 'available') {
            const regUrl = data.domain.endsWith('.br')
                ? `https://registro.br/busca-dominio/?pesquisa=${encodeURIComponent(data.domain)}`
                : `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(data.domain)}`;

            html += `
                <a href="${regUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-success py-1 px-3 fw-semibold" title="Comprar / Registrar este domínio">
                    <i class="bi bi-cart-check me-1"></i> Comprar
                </a>
                <button type="button" class="btn btn-sm btn-outline-primary py-1 px-2 btn-view-details" data-domain="${escapeHtml(data.domain)}" title="Ver detalhes">
                    <i class="bi bi-info-circle"></i>
                </button>
            `;
        } else {
            html += `
                <button type="button" class="btn btn-sm btn-outline-primary py-1 px-2 btn-view-details" data-domain="${escapeHtml(data.domain)}" title="Ver todos os detalhes do WHOIS">
                    <i class="bi bi-info-circle me-1"></i> Detalhes
                </button>
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

        const cells = tr.querySelectorAll('td');
        if (cells.length >= 7) {
            cells[1].innerHTML = getRowBadgeHtml(data);
            cells[5].textContent = data.registrar || '-';
            cells[6].innerHTML = getRowActionsHtml(data);
            bindRowActions(tr);
        }
    }

    function bindRowActions(container) {
        container.querySelectorAll('.btn-view-details').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const domain = btn.dataset.domain;
                const item = allResults.find(r => r.domain.toLowerCase() === domain.toLowerCase());
                if (item) openWhoisModal(item);
            };
        });

        container.querySelectorAll('.btn-copy-domain').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const domain = btn.dataset.domain;
                copyToClipboard(domain);
                showToast(`Domínio <strong>${domain}</strong> copiado!`, 'success');
            };
        });
    }

    // --- 6. Paginação ---
    function updatePaginationInfo() {
        const total = filteredResults.length;
        if (total === 0) {
            paginationInfo.textContent = 'Nenhum domínio a exibir';
            paginationContainer.innerHTML = '';
            return;
        }
        const startIndex = (currentPage - 1) * pageSize + 1;
        const endIndex = pageSize === Infinity ? total : Math.min(currentPage * pageSize, total);
        paginationInfo.innerHTML = `Exibindo <strong>${startIndex}</strong> a <strong>${endIndex}</strong> de <strong>${total}</strong> extensões ${allResults.length > total ? `(filtradas de ${allResults.length})` : ''}`;
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

    // --- 7. Modal de Detalhes WHOIS ---
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
            badgeEl.textContent = 'Limite Atingido';
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
            eppContainer.innerHTML = '<span class="text-muted small">-</span>';
        }

        document.getElementById('modalCreationDate').textContent = item.creation_date || '-';
        document.getElementById('modalUpdatedDate').textContent = item.updated_date || '-';
        document.getElementById('modalExpirationDate').textContent = item.expiration_date || '-';

        document.getElementById('modalRawText').textContent = item.raw_text || 'Sem resposta bruta disponível.';

        const btnModalRegister = document.getElementById('btnModalRegister');
        if (item.status === 'available') {
            btnModalRegister.style.display = 'inline-block';
            btnModalRegister.href = item.domain.endsWith('.br')
                ? `https://registro.br/busca-dominio/?pesquisa=${encodeURIComponent(item.domain)}`
                : `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(item.domain)}`;
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

    // --- 8. Exportação e Cópia ---
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
            a.download = filter === 'available' ? `dominios_disponiveis_${currentKeyword}.csv` : `relatorio_${currentKeyword}.csv`;
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

    function showToast(message, type = 'dark') {
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

    // Inicialização
    loadTlds();
});
