// catchall.mx - DNS tool pages and small helpers shared by the guides.
(function () {
    const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g,
        (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    const ICON = {success: '✓', error: '✗', warning: '!', info: '→'};
    const NAMES = {
        mx: ['MX records', '/tools/mx-lookup/'], spf: ['SPF', '/tools/spf-checker/'],
        dkim: ['DKIM', '/tools/dkim-checker/'], dmarc: ['DMARC', '/tools/dmarc-checker/'],
    };

    // Copy buttons, anywhere on the page
    document.addEventListener('click', (e) => {
        const b = e.target.closest('.copy');
        if (!b) return;
        const done = () => {
            b.classList.add('done'); b.textContent = 'Copied';
            setTimeout(() => { b.classList.remove('done'); b.textContent = 'Copy'; }, 1400);
        };
        const text = b.dataset.copy;
        if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => {});
    });

    function renderOne(r, linkKind) {
        const s = r.summary || {level: 'info', text: ''};
        const name = NAMES[r.tool] || [r.tool, ''];
        const kind = linkKind
            ? `<span class="kind"><a href="${name[1]}?domain=${encodeURIComponent(r.domain)}">${esc(name[0])} →</a></span>`
            : `<span class="kind">${esc(name[0])} for ${esc(r.domain)}</span>`;
        let h = `<div class="res"><div class="res-head ${s.level}"><span class="ic">${ICON[s.level] || ''}</span><div>${kind}<b>${esc(s.text)}</b></div></div>`;
        (r.records || []).forEach((x) => {
            h += `<div class="rec"><span class="t">${esc(x.label)}</span><span class="v">${esc(x.value)}</span><button class="copy" data-copy="${esc(x.value)}">Copy</button></div>`;
        });
        if ((r.details || []).length) {
            h += '<table>' + r.details.map((d) => `<tr><td>${esc(d[0])}</td><td>${esc(d[1])}</td></tr>`).join('') + '</table>';
        }
        (r.notes || []).forEach((n) => {
            h += `<div class="note ${n.level}"><span class="ic">${ICON[n.level] || ''}</span><div>${esc(n.text)}${n.fix ? `<span class="fix">${esc(n.fix)}</span>` : ''}</div></div>`;
        });
        return h + '</div>';
    }

    const box = document.querySelector('[data-tool]');
    if (box) {
        const tool = box.dataset.tool;
        const input = box.querySelector('#domain');
        const sel = box.querySelector('#selector');
        const btn = box.querySelector('button.btn');
        const out = box.querySelector('#out');
        const label = btn.textContent;

        async function run() {
            const domain = input.value.trim();
            if (!domain) { out.innerHTML = '<div class="res plain error">Enter a domain first, for example example.com.</div>'; input.focus(); return; }
            btn.disabled = true; btn.textContent = 'Looking…';
            out.innerHTML = '<div class="res loading">Reading DNS records…</div>';
            let url = `/api/tools/${tool}?domain=${encodeURIComponent(domain)}`;
            if (sel && sel.value.trim()) url += `&selector=${encodeURIComponent(sel.value.trim())}`;
            try {
                const data = await (await fetch(url)).json();
                if (data.error) out.innerHTML = `<div class="res plain error">${esc(data.error)}</div>`;
                else {
                    out.innerHTML = data.results ? data.results.map((x) => renderOne(x, true)).join('') : renderOne(data, false);
                    const q = new URLSearchParams({domain: data.domain});
                    if (sel && sel.value.trim()) q.set('selector', sel.value.trim());
                    history.replaceState(null, '', location.pathname + '?' + q);
                }
            } catch (e) {
                out.innerHTML = '<div class="res plain error">The lookup did not go through. Please try again.</div>';
            } finally { btn.disabled = false; btn.textContent = label; }
        }
        btn.addEventListener('click', run);
        box.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.tagName === 'INPUT') run(); });
        const q = new URLSearchParams(location.search);
        if (sel && q.get('selector')) sel.value = q.get('selector');
        if (q.get('domain')) { input.value = q.get('domain'); run(); }
    }

    // Guides: typing your own address fills it into the records on the page
    const fwd = document.getElementById('fwd');
    if (fwd) {
        const apply = () => {
            const v = fwd.value.trim() || 'you@example.com';
            document.querySelectorAll('[data-fwd]').forEach((el) => {
                const text = el.dataset.fwd.replace('{a}', v);
                el.textContent = text;
                const b = el.parentElement.querySelector('.copy');
                if (b) b.dataset.copy = text;
            });
        };
        fwd.addEventListener('input', apply);
    }
    const go = document.getElementById('check-go');
    if (go) {
        const d = document.getElementById('check-domain');
        const open = () => { if (d.value.trim()) location.href = '/?domain=' + encodeURIComponent(d.value.trim()); else d.focus(); };
        go.addEventListener('click', open);
        d.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
    }
})();
