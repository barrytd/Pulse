// history.js — Score history page. Uses its own chart instance
// (separate from dashboard's score chart) so the two can coexist.
(function () {
  'use strict';

  var _historyChartInstance = null;
  var _historyHighlightIdx  = -1;

  async function renderHistoryPage() {
    var c = document.getElementById('content');
    var scans = await window.fetchScans(200);

    if (scans.length === 0) {
      c.innerHTML =
        '<div class="empty-state cta">' +
          '<div class="empty-icon">&#128200;</div>' +
          '<h3>No history yet</h3>' +
          '<p>Run your first scan to start tracking your security posture over time.</p>' +
          '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
        '</div>';
      return;
    }

    var withScore = scans.filter(function (s) { return s.score != null; });
    var avg  = withScore.length
      ? Math.round(withScore.reduce(function (a, s) { return a + s.score; }, 0) / withScore.length)
      : '-';
    var best = withScore.length
      ? Math.max.apply(null, withScore.map(function (s) { return s.score; }))
      : '-';
    var worst = withScore.length
      ? Math.min.apply(null, withScore.map(function (s) { return s.score; }))
      : '-';

    c.innerHTML =
      '<div class="page-head">' +
        '<div class="page-head-title"><strong>' + scans.length + '</strong> scans tracked</div>' +
      '</div>' +

      '<div class="summary-row">' +
        window._trendStatCard('Average Score', avg, 'Across all scans', null, window._accentForScore(avg === '-' ? null : avg), window.scoreColorClass(avg === '-' ? null : avg)) +
        window._trendStatCard('Best Score',  best, 'Highest recorded', null, 'accent-info', window.scoreColorClass(best === '-' ? null : best)) +
        window._trendStatCard('Worst Score', worst, 'Lowest recorded', null, 'accent-critical', window.scoreColorClass(worst === '-' ? null : worst)) +
        window._trendStatCard('Total Scans', scans.length, 'Runs to date', null, 'accent-neutral') +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Security Score Trend</div>' +
        '<div class="score-chart-wrap" style="height:220px;"><canvas id="history-line-chart"></canvas></div>' +
      '</div>' +

      '<div class="card" style="padding:0; overflow:hidden;">' +
        _buildHistoryTable(scans) +
      '</div>';

    _initHistoryLineChart(scans);
  }

  function _buildHistoryTable(scans) {
    return '<table class="data-table">' +
      '<thead><tr>' +
        '<th>Date / Time</th><th>File</th><th>Findings</th><th>Score</th><th>Grade</th><th>Trend</th>' +
      '</tr></thead><tbody>' +
      scans.map(function (scan, i) {
        var grade = window._gradeFor(scan.score);
        var trend = '<span class="trend-flat">=</span>';
        if (i < scans.length - 1 && scan.score != null && scans[i + 1].score != null) {
          var diff = scan.score - scans[i + 1].score;
          if (diff > 0) trend = '<span class="trend-up">\u2191 +' + diff + '</span>';
          else if (diff < 0) trend = '<span class="trend-down">\u2193 ' + diff + '</span>';
        }
        return '<tr class="clickable history-row" data-scan-id="' + scan.id + '" ' +
          'data-action="highlightHistoryScan" data-arg="' + scan.id + '">' +
          '<td>' + window.escapeHtml(scan.scanned_at || '-') + '</td>' +
          '<td style="color:var(--text-muted);">' + window.escapeHtml(scan.filename || 'Unknown') + '</td>' +
          '<td>' + scan.total_findings + '</td>' +
          '<td style="font-weight:700; color:' + window.scoreColor(scan.score) + '">' +
            (scan.score != null ? scan.score : '-') + '</td>' +
          '<td>' + (grade ? '<span class="grade-pill grade-' + grade + '">' + grade + '</span>' : '-') + '</td>' +
          '<td>' + trend + '</td>' +
        '</tr>';
      }).join('') +
      '</tbody></table>';
  }

  // Clicking a table row highlights the matching point on the chart.
  function highlightHistoryScan(scanId, rowEl) {
    // scanId may arrive as a string via data-arg; normalize to number.
    scanId = Number(scanId);
    document.querySelectorAll('.history-row.highlight').forEach(function (r) {
      if (r !== rowEl) r.classList.remove('highlight');
    });
    var isAlready = rowEl.classList.toggle('highlight');

    if (!_historyChartInstance) return;

    if (!isAlready) {
      _historyHighlightIdx = -1;
    } else {
      var labels = _historyChartInstance.data._scanIds || [];
      _historyHighlightIdx = labels.indexOf(scanId);
    }
    _historyChartInstance.update('none');
  }

  function _initHistoryLineChart(scans) {
    if (typeof Chart === 'undefined') return;
    var canvas = document.getElementById('history-line-chart');
    if (!canvas) return;

    var series = scans.slice().reverse();
    var labels = series.map(function (s) { return (s.scanned_at || '').split(' ')[0] || '-'; });
    var scores = series.map(function (s) { return s.score; });
    var scanIds = series.map(function (s) { return s.id; });

    var styles = getComputedStyle(document.documentElement);
    var accent     = styles.getPropertyValue('--accent').trim() || '#58a6ff';
    var textMuted  = styles.getPropertyValue('--text-muted').trim() || '#8b949e';
    var border     = styles.getPropertyValue('--border').trim() || '#30363d';

    if (_historyChartInstance) { _historyChartInstance.destroy(); }

    _historyChartInstance = new Chart(canvas.getContext('2d'), {
      type: 'line',
      data: {
        labels: labels,
        _scanIds: scanIds,
        datasets: [{
          data: scores,
          borderColor: accent,
          backgroundColor: accent + '22',
          borderWidth: 2,
          fill: true,
          tension: 0.3,
          pointBackgroundColor: function (ctx) {
            return ctx.dataIndex === _historyHighlightIdx ? '#f85149' : accent;
          },
          pointBorderColor: function (ctx) {
            return ctx.dataIndex === _historyHighlightIdx ? '#f85149' : accent;
          },
          pointRadius: function (ctx) {
            return ctx.dataIndex === _historyHighlightIdx ? 6 : 3;
          },
          pointHoverRadius: 6,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend:  { display: false },
          tooltip: {
            callbacks: {
              title: function (items) {
                var i = items[0].dataIndex;
                return series[i].scanned_at || '';
              },
              label: function (item) {
                return 'Score: ' + item.parsed.y;
              }
            }
          }
        },
        scales: {
          x: {
            ticks: { color: textMuted, font: { size: 10 } },
            grid:  { display: false },
            border: { color: border },
          },
          y: {
            min: 0, max: 100,
            ticks: { color: textMuted, font: { size: 10 }, stepSize: 25 },
            grid:  { display: false },
            border: { color: border },
          }
        }
      }
    });
  }

  window.renderHistoryPage    = renderHistoryPage;
  window.highlightHistoryScan = highlightHistoryScan;
})();
