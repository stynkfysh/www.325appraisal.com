/* 325 Appraisal — site script */
(function () {
  // Mobile navigation
  var btn = document.querySelector('.nav-toggle');
  var nav = document.querySelector('.nav-links');
  if (btn && nav) {
    btn.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    nav.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', function () { nav.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); });
    });
  }

  var form = document.querySelector('form[action="/api/contact"]');
  if (!form) return;
  var params = new URLSearchParams(window.location.search);

  // Result banner after submission
  var status = params.get('status');
  var ok = document.getElementById('form-success');
  var err = document.getElementById('form-error');
  if (status === 'success' && ok) {
    ok.style.display = 'block'; form.style.display = 'none';
    var card = form.closest('.form-card');
    if (card) card.querySelectorAll('h2').forEach(function (h) { h.style.display = 'none'; });
    ok.scrollIntoView({ block: 'center' });
  }
  if (status === 'error' && err) { err.style.display = 'block'; err.scrollIntoView({ block: 'center' }); }

  // Pre-fill from links such as /contact?purpose=divorce or /contact?city=Carlsbad
  var purpose = form.querySelector('select[name="appraisal-purpose"]');
  var type = form.querySelector('select[name="appraisal-type"]');
  var city = form.querySelector('input[name="city"]');
  var p = params.get('purpose');
  if (p && purpose && purpose.querySelector('option[value="' + p.replace(/[^a-z0-9-]/g, '') + '"]')) purpose.value = p;
  var t = params.get('type');
  if (t && type && type.querySelector('option[value="' + t.replace(/[^a-z0-9-]/g, '') + '"]')) type.value = t;
  var c = params.get('city');
  if (c && city && !/county|san francisco/i.test(c)) city.value = c.slice(0, 60);
  if (c && /county/i.test(c)) {
    var msg = form.querySelector('textarea[name="message"]');
    if (msg && !msg.value) msg.value = 'Property is in ' + c.slice(0, 60) + '. ';
  }

  // Date-of-death field appears only for that purpose
  var dodWrap = document.getElementById('dod-field');
  var dod = document.getElementById('date-of-death');
  var eff = document.getElementById('eff-field');
  var today = new Date().toISOString().slice(0, 10);
  if (dod) dod.max = today;
  var effIn = document.getElementById('effective-date');
  if (effIn) effIn.max = today;
  function syncDod() {
    var on = purpose && purpose.value === 'date-of-death';
    if (dodWrap) dodWrap.hidden = !on;
    if (dod) dod.required = !!on;
    if (eff) eff.hidden = !!on;
  }
  if (purpose) { purpose.addEventListener('change', syncDod); syncDod(); }

  // Signed form token: lets the server tell a real page visit from a scripted POST
  fetch('/api/form-token', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var f = form.querySelector('input[name="form_token"]');
      if (f && d && d.token) f.value = d.token;
    })
    .catch(function () { /* non-blocking */ });
})();
