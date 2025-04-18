﻿# -------------------------------------------------------------------
# Purview_audit_to_HTML.ps1
# Reads a Purview audit-export CSV (AuditData JSON)
# Writes one self‑contained HTML viewer with:
#  • Only the default Purview columns
#  • Humanized Activity names
#  • Styled code boxes in the Details pane
# -------------------------------------------------------------------

# 1) CONFIGURE: hard‑coded paths
$InputCsv   = 'CSVFILEPATHHERE.CSV'
$OutputHtml = 'OUTPUTFILEPATHHERE.html'

# 2) IMPORT & PARSE
$rows = Import-Csv -Path $InputCsv
$data = foreach ($row in $rows) {
    $obj = $row.AuditData | ConvertFrom-Json
    $obj | Add-Member -NotePropertyName _raw `
                      -NotePropertyValue $row.AuditData `
                      -Force
    $obj
}

# 3) SERIALIZE to JSON for embedding
$json = $data | ConvertTo-Json -Depth 10

# 4) HTML template
$htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Purview Audit Report Viewer</title>
  <link rel="stylesheet"
        href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
  <style>
    body { margin:0; overflow:hidden; font-family:Segoe UI,Arial,sans-serif; }
    #container { display:flex; height:100vh; width:100vw; }
    #table-area { flex:1; padding:16px; overflow:auto; }
    table.dataTable { width:100% !important; }

    /* Overlay */
    #overlay {
      position:fixed; top:0; left:0;
      width:100vw; height:100vh;
      background:rgba(0,0,0,0.3);
      opacity:0; visibility:hidden;
      transition:opacity .3s,visibility .3s;
      z-index:99;
    }
    #overlay.show { opacity:1; visibility:visible; }

    /* Sidebar */
    #sidebar {
      position:fixed; top:0; right:-420px;
      width:420px; height:100vh;
      background:#fff; box-shadow:-2px 0 8px rgba(0,0,0,0.2);
      transition:right .3s; overflow-y:auto; z-index:100;
    }
    #sidebar.open { right:0; }
    #sidebar .sidebar-header {
      display:flex; justify-content:space-between;
      align-items:center; padding:16px; border-bottom:1px solid #ddd;
    }
    #sidebar .sidebar-header h2 { margin:0; font-size:1.2em; }
    #sidebar .sidebar-header button {
      background:none; border:none; font-size:1.2em; cursor:pointer;
    }
    #sidebar .sidebar-content { padding:16px; }
    #sidebar .field { margin-bottom:16px; }
    #sidebar .label { font-weight:600; margin-bottom:4px; }
    /* styled code box */
    #sidebar pre.value {
      background:#f4f4f4;
      padding:8px;
      border-radius:4px;
      font-family:Consolas,monospace;
      font-size:.9em;
      overflow:auto;
    }
    #sidebar .value { white-space:pre-wrap; word-break:break-word; }
  </style>
</head>
<body>
  <div id="container">
    <div id="table-area">
      <h1>Purview Audit Report</h1>
      <table id="auditTable" class="display"><thead></thead><tbody></tbody></table>
    </div>

    <div id="sidebar">
      <div class="sidebar-header">
        <h2>Details</h2>
        <button id="close-sidebar">✖</button>
      </div>
      <div class="sidebar-content"></div>
    </div>
    <div id="overlay"></div>
  </div>

  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
  <script>
    // embedded data
    const auditData = __JSON__;

    // map raw operation → friendly label
    const opMap = {
      MailItemsAccessed: 'Accessed mailbox items',
      MailItemsViewed:   'Viewed mailbox items',
      MailItemsDeleted:  'Deleted mailbox items',
      CompanyLinkUsed:   'Used a company shareable link',
      PurgedMessages:    'Purged messages',
      UpdatedMessage:    'Updated message',
      CreatedMailboxItem:'Created mailbox item',
      UserLoggedIn:      'Signed in',
      // …add or tweak as needed…
    };

    function humanOp(raw) {
      if (opMap[raw]) { return opMap[raw]; }
      // fallback: split CamelCase → words
      return raw.replace(/([A-Z])/g,' $1').trim();
    }

    $(document).ready(function() {
      // 1) default Purview columns
      const visibleCols = [
        { key:'CreationTime', title:'Date (UTC)'   },
        { key:'ClientIP',     title:'IP Address'   },
        { key:'UserId',       title:'User'         },
        { key:'RecordType',   title:'Record Type' },
        { key:'Operation',    title:'Activity',
          render: d => humanOp(d) },
        { key:'ObjectId',     title:'Item'         },
        { key:'AdminUnits',   title:'Admin Units' }
      ];

      // 2) build DataTables column defs
      const columns = visibleCols.map(c => ({
        data: c.key,
        title: c.title,
        defaultContent: '',
        render: c.render
      }));

      // 3) init DataTable
      const table = $('#auditTable').DataTable({
        data: auditData,
        columns: columns,
        order: [[0,'desc']],
        pageLength:25,
        autoWidth:false
      });

      // 4) sidebar logic
      const $sidebar = $('#sidebar'),
            $overlay = $('#overlay'),
            $content = $sidebar.find('.sidebar-content');

      function openSidebar(row) {
        $content.empty();
        Object.keys(row).forEach(k => {
          if (k===' _raw') return;
          const val = row[k];
          const $f = $('<div>').addClass('field');
          $('<div>').addClass('label').text(k).appendTo($f);

          if (val!==null && typeof val==='object') {
            $('<pre>').addClass('value').text(JSON.stringify(val,null,2)).appendTo($f);
          }
          else {
            $('<div>').addClass('value').text(val).appendTo($f);
          }
          $content.append($f);
        });
        $overlay.addClass('show');
        $sidebar.addClass('open');
      }
      function closeSidebar() {
        $overlay.removeClass('show');
        $sidebar.removeClass('open');
      }
      $('#close-sidebar, #overlay').on('click',closeSidebar);

      // 5) row-click → open sidebar
      $('#auditTable tbody').on('click','tr',function(){
        const d = table.row(this).data();
        if (d) { openSidebar(d); }
      });
    });
  </script>
</body>
</html>
'@

# 5) INJECT JSON
$html = $htmlTemplate -replace '__JSON__', $json

# 6) WRITE OUT
Set-Content -Path $OutputHtml -Value $html -Encoding UTF8
Write-Host "✔ Generated standalone viewer at $OutputHtml"
                                                                             