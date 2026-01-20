const BASE_PATH = '.';
const DATA_URL = './data.json';

const els = {
  q: document.getElementById('q'),
  clear: document.getElementById('clear'),
  nav: document.getElementById('nav'),
  main: document.getElementById('main'),
  modsCount: document.getElementById('modsCount'),
  funcsCount: document.getElementById('funcsCount'),
  shownCount: document.getElementById('shownCount'),
  toast: document.getElementById('toast'),
  breadcrumbText: document.getElementById('breadcrumbText'),
  jumpTop: document.getElementById('jumpTop'),
};

const psm1Cache = new Map();
const codeCache = new Map();

function slugify(s) {
  return s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-{2,}/g, '-').replace(/^-|-$/g, '') || 'section';
}

function showToast(text) {
  els.toast.textContent = text;
  els.toast.classList.add('show');
  window.clearTimeout(showToast._t);
  showToast._t = window.setTimeout(() => els.toast.classList.remove('show'), 1200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied: ' + text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Copied: ' + text);
  }
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractFunctionCode(psm1Text, funcName) {
  const regex = new RegExp(`^\\s*function\\s+${escapeRegExp(funcName)}\\b`, 'm');
  const match = regex.exec(psm1Text);
  if (!match) return '';

  let idx = match.index;
  const braceIdx = psm1Text.indexOf('{', idx);
  if (braceIdx === -1) return '';

  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let inHereSingle = false;
  let inHereDouble = false;

  for (let i = braceIdx; i < psm1Text.length; i += 1) {
    const ch = psm1Text[i];
    const next = psm1Text[i + 1];

    if (!inSingle && !inDouble && !inHereSingle && !inHereDouble) {
      if (ch === '@' && next === '\'') {
        inHereSingle = true;
        i += 1;
        continue;
      }
      if (ch === '@' && next === '"') {
        inHereDouble = true;
        i += 1;
        continue;
      }
    }

    if (inHereSingle) {
      if (ch === '\'' && psm1Text[i - 1] === '\n') {
        inHereSingle = false;
      }
      continue;
    }

    if (inHereDouble) {
      if (ch === '"' && psm1Text[i - 1] === '\n') {
        inHereDouble = false;
      }
      continue;
    }

    if (!inDouble && ch === '\'' && psm1Text[i - 1] !== '`') {
      inSingle = !inSingle;
      continue;
    }

    if (!inSingle && ch === '"' && psm1Text[i - 1] !== '`') {
      inDouble = !inDouble;
      continue;
    }

    if (inSingle || inDouble) continue;

    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        return psm1Text.slice(match.index, i + 1).trim();
      }
    }
  }

  return '';
}

async function fetchPsm1(path) {
  if (!path) return '';
  if (psm1Cache.has(path)) return psm1Cache.get(path);
  const res = await fetch(`${BASE_PATH}/${path}`);
  if (!res.ok) return '';
  const text = await res.text();
  psm1Cache.set(path, text);
  return text;
}

async function renderCode(panel, item) {
  if (!panel || panel.dataset.rendered === 'true') return;

  let code = '';
  if (item.psm1) {
    const key = `${item.psm1}::${item.name}`;
    if (codeCache.has(key)) {
      code = codeCache.get(key);
    } else {
      const psm1Text = await fetchPsm1(item.psm1);
      code = extractFunctionCode(psm1Text, item.name);
      codeCache.set(key, code);
    }
  }

  const pre = document.createElement('pre');
  const codeEl = document.createElement('code');
  codeEl.className = 'language-powershell';
  codeEl.textContent = code || 'No code found.';
  pre.appendChild(codeEl);
  panel.appendChild(pre);
  if (window.hljs) {
    hljs.highlightElement(codeEl);
  }
  panel.dataset.rendered = 'true';
}

function buildUI(data) {
  const totalFunctions = data.reduce((a, m) => a + m.items.length, 0);
  els.modsCount.textContent = data.length;
  els.funcsCount.textContent = totalFunctions;

  const navFrag = document.createDocumentFragment();
  const mainFrag = document.createDocumentFragment();

  for (const mod of data) {
    const id = slugify(mod.name);

    const a = document.createElement('a');
    a.href = `#${id}`;
    a.dataset.module = mod.name;

    let icon = null;
    if (mod.icon) {
      icon = document.createElement('img');
      icon.className = 'nav-icon';
      icon.src = `${BASE_PATH}/${mod.icon}`;
      icon.alt = '';
    }

    const nameText = document.createElement('span');
    nameText.className = 'nav-name';
    nameText.textContent = mod.name;

    const count = document.createElement('span');
    count.className = 'count';
    count.textContent = mod.items.length;

    if (icon) a.appendChild(icon);
    a.appendChild(nameText);
    a.appendChild(count);
    navFrag.appendChild(a);

    const section = document.createElement('section');
    section.className = 'section';
    section.id = id;
    section.dataset.module = mod.name;

    const head = document.createElement('div');
    head.className = 'section-head';
    const title = document.createElement('h2');
    const titleWrap = document.createElement('span');
    titleWrap.className = 'section-title';

    if (mod.icon) {
      const iconLg = document.createElement('img');
      iconLg.className = 'module-icon-lg';
      iconLg.src = `${BASE_PATH}/${mod.icon}`;
      iconLg.alt = '';
      titleWrap.appendChild(iconLg);
    }

    const titleText = document.createElement('span');
    titleText.textContent = mod.name;
    titleWrap.appendChild(titleText);
    title.appendChild(titleWrap);

    const meta = document.createElement('div');
    meta.className = 'section-meta';
    meta.innerHTML = `<span class="shown">${mod.items.length}</span> / ${mod.items.length} shown`;

    head.appendChild(title);
    head.appendChild(meta);
    section.appendChild(head);

    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Function</th></tr></thead>';
    const tbody = document.createElement('tbody');

    for (const item of mod.items) {
      const tr = document.createElement('tr');
      tr.dataset.func = item.name;
      tr.dataset.desc = item.desc;

      const tdFunc = document.createElement('td');
      const wrap = document.createElement('div');
      wrap.className = 'func-cell';
      const code = document.createElement('code');
      code.className = 'func-pill';
      code.textContent = item.name;
      const chev = document.createElement('span');
      chev.className = 'chev';
      chev.textContent = '>';
      code.appendChild(chev);
      const btn = document.createElement('button');
      btn.className = 'btn copy';
      btn.type = 'button';
      btn.textContent = 'Copy name';
      btn.addEventListener('click', () => copyText(item.name));
      wrap.appendChild(code);
      wrap.appendChild(btn);
      tdFunc.appendChild(wrap);

      tr.appendChild(tdFunc);
      tbody.appendChild(tr);

      const codeRow = document.createElement('tr');
      codeRow.className = 'code-row hidden';
      const codeTd = document.createElement('td');
      codeTd.colSpan = 1;
      const panel = document.createElement('div');
      panel.className = 'code-panel';
      panel.dataset.rendered = 'false';

      const desc = document.createElement('div');
      desc.className = 'code-desc';
      const descTitle = document.createElement('div');
      descTitle.className = 'code-desc-title';
      descTitle.textContent = 'Description';
      const descBody = document.createElement('div');
      descBody.textContent = item.desc;
      desc.appendChild(descTitle);
      desc.appendChild(descBody);

      const actions = document.createElement('div');
      actions.className = 'code-actions';
      const copyCode = document.createElement('button');
      copyCode.className = 'btn';
      copyCode.type = 'button';
      copyCode.textContent = 'Copy code';
      copyCode.addEventListener('click', () => copyText(codeCache.get(`${item.psm1}::${item.name}`) || ''));
      actions.appendChild(copyCode);

      panel.appendChild(desc);
      panel.appendChild(actions);
      codeTd.appendChild(panel);
      codeRow.appendChild(codeTd);
      tbody.appendChild(codeRow);

      code.addEventListener('click', async () => {
        codeRow.classList.toggle('hidden');
        const isOpen = !codeRow.classList.contains('hidden');
        code.classList.toggle('open', isOpen);
        codeRow.classList.toggle('open', isOpen);
        if (isOpen) {
          await renderCode(panel, item);
        }
      });
    }

    table.appendChild(tbody);
    section.appendChild(table);
    mainFrag.appendChild(section);
  }

  els.nav.appendChild(navFrag);
  els.main.appendChild(mainFrag);
  filter('');
}

function filter(query) {
  const q = query.trim().toLowerCase();
  let shown = 0;

  for (const section of els.main.querySelectorAll('.section')) {
    let sectionShown = 0;
    for (const row of section.querySelectorAll('tbody tr')) {
      if (row.classList.contains('code-row')) {
        row.classList.add('hidden');
        continue;
      }
      const hay = (row.dataset.func + ' ' + row.dataset.desc).toLowerCase();
      const match = !q || hay.includes(q);
      row.classList.toggle('hidden', !match);
      if (match) {
        sectionShown += 1;
        shown += 1;
      }
    }

    section.classList.toggle('hidden', sectionShown === 0);
    const shownEl = section.querySelector('.shown');
    if (shownEl) shownEl.textContent = sectionShown;

    const navLink = els.nav.querySelector(`a[data-module="${CSS.escape(section.dataset.module)}"]`);
    if (navLink) navLink.classList.toggle('hidden', sectionShown === 0);
  }

  els.shownCount.textContent = shown;
}

function updateBreadcrumb() {
  const sections = [...els.main.querySelectorAll('.section:not(.hidden)')];
  const scrollTop = window.scrollY + 80;
  let current = 'All Modules';
  for (const section of sections) {
    if (section.offsetTop <= scrollTop) {
      current = section.dataset.module || current;
    }
  }
  els.breadcrumbText.textContent = current;
  els.jumpTop.classList.toggle('show', window.scrollY > 240);
}

els.q.addEventListener('input', (e) => filter(e.target.value));
els.clear.addEventListener('click', () => {
  els.q.value = '';
  filter('');
  els.q.focus();
});

els.jumpTop.addEventListener('click', () => {
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

window.addEventListener('scroll', () => {
  window.requestAnimationFrame(updateBreadcrumb);
});

fetch(DATA_URL)
  .then((res) => res.json())
  .then((data) => {
    buildUI(data);
    updateBreadcrumb();
  })
  .catch(() => {
    els.main.innerHTML = '<div class="section">Failed to load data.json</div>';
  });
