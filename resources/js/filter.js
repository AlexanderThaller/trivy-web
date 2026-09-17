// Client side filtering of the findings tables.
//
// The tables stream into the page after this file has run, so nothing here
// looks anything up at load time: the listeners are delegated from the body
// and every call resolves its table again. The initial "N vulnerabilities"
// count is rendered by the server, so the first paint is already correct and
// this only ever runs in response to the user touching a toolbar.
//
// One toolbar per scanner -- trivy's findings and grype's matches each have
// their own, and each says which table it filters in `data-table`, so this
// stays one piece of code rather than one per table.

function filterTable(toolbar) {
  var table = document.getElementById(toolbar.dataset.table);
  if (!table) {
    return;
  }

  var needle = toolbar.querySelector('.filter-input').value.trim().toLowerCase();
  var severities = new Set(
    Array.from(toolbar.querySelectorAll('input[type=checkbox]:checked')).map(
      function (checkbox) {
        return checkbox.value;
      }
    )
  );

  var rows = table.tBodies[0].rows;
  var shown = 0;

  for (var index = 0; index < rows.length; index += 1) {
    var row = rows[index];

    if (!row.dataset.haystack) {
      row.dataset.haystack = row.textContent.toLowerCase().replace(/\s+/g, ' ');
    }

    var visible =
      severities.has(row.className) &&
      (needle === '' || row.dataset.haystack.includes(needle));

    row.hidden = !visible;
    if (visible) {
      shown += 1;
    }
  }

  var count = toolbar.querySelector('.filter-count');
  if (count) {
    count.textContent =
      shown === rows.length
        ? `${rows.length} findings`
        : `${shown} of ${rows.length} findings`;
  }
}

function onToolbarEvent(event) {
  var toolbar = event.target.closest('.toolbar[data-table]');
  if (toolbar) {
    filterTable(toolbar);
  }
}

document.body.addEventListener('input', onToolbarEvent);
document.body.addEventListener('change', onToolbarEvent);
