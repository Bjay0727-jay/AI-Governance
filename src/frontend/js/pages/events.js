export const events = {
  bindPageEvents(page) {
    switch (page) {
      case 'ai-assets':
        document.getElementById('btn-add-asset')?.addEventListener('click', () => this.showAssetForm());
        break;
      case 'risk-assessments':
        document.getElementById('btn-add-risk')?.addEventListener('click', () => this.showRiskForm());
        break;
      case 'vendors':
        document.getElementById('btn-add-vendor')?.addEventListener('click', () => this.showVendorForm());
        break;
      case 'maturity':
        document.getElementById('btn-add-maturity')?.addEventListener('click', () => this.showMaturityForm());
        break;
      case 'incidents':
        document.getElementById('btn-add-incident')?.addEventListener('click', () => this.showIncidentForm());
        break;
      case 'impact-assessments':
        document.getElementById('btn-add-aia')?.addEventListener('click', () => this.showImpactForm());
        break;
      case 'users':
        document.getElementById('btn-add-user')?.addEventListener('click', () => this.showUserForm());
        break;
      case 'support':
        document.getElementById('btn-add-ticket')?.addEventListener('click', () => this.showTicketForm());
        break;
      case 'feature-requests':
        document.getElementById('btn-add-feature')?.addEventListener('click', () => this.showFeatureForm());
        break;
    }
  },
};
