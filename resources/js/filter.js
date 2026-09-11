// Client side filtering of the findings table.
//
// The table streams into the page after this file has run, so nothing here
// looks anything up at load time: the listeners are delegated from the body
// and every call resolves the table again. The initial "N vulnerabilities"
// count is rendered by the server, so the first paint is already correct and
// this only ever runs in response to the user touching the toolbar.

function filterVulnerabilities() {
  var table = document.getElementById('cves');
  if (!table) {
    return;
  }

  var toolbar = document.getElementById('cve_filter');
  var needle = '';
  var severities = null;

  if (toolbar) {
    needle = toolbar.querySelector('.filter-input').value.trim().toLowerCase();
    severities = new Set(
      Array.from(toolbar.querySelectorAll('input[type=checkbox]:checked')).map(
        function (checkbox) {
          return checkbox.value;
        }
      )
    );
  }

  var rows = table.tBodies[0].rows;
  var shown = 0;

  for (var index = 0; index < rows.length; index += 1) {
    var row = rows[index];

    if (!row.dataset.haystack) {
      row.dataset.haystack = row.textContent.toLowerCase().replace(/\s+/g, ' ');
    }

    var visible =
      (severities === null || severities.has(row.className)) &&
      (needle === '' || row.dataset.haystack.includes(needle));

    row.hidden = !visible;
    if (visible) {
      shown += 1;
    }
  }

  var count = document.getElementById('cve_count');
  if (count) {
    count.textContent =
      shown === rows.length
        ? `${rows.length} vulnerabilities`
        : `${shown} of ${rows.length} vulnerabilities`;
  }
}

document.body.addEventListener('input', function (event) {
  if (event.target.closest('#cve_filter')) {
    filterVulnerabilities();
  }
});

document.body.addEventListener('change', function (event) {
  if (event.target.closest('#cve_filter')) {
    filterVulnerabilities();
  }
});
