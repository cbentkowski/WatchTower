try { document.documentElement.dataset.theme = localStorage.getItem('dashboard-theme') || 'light'; } catch { document.documentElement.dataset.theme = 'light'; }
