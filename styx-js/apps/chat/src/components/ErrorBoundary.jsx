import { Component } from 'react';

// Last line of defence for the whole UI: an exception thrown while rendering is
// shown as a recoverable error screen instead of an empty page. The chat data is
// not touched; reloading restarts the app, which cleans malformed stored records
// when it loads them.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error) {
    // Only the error name reaches the console: message text may carry chat content.
    console.error('Styx UI render error:', error?.name || 'Error');
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="fatal" role="alert" data-testid="render-error">
        <h1>Si è verificato un errore imprevisto</h1>
        <p>L'interfaccia non è riuscita a mostrare questa schermata. I tuoi dati non sono stati modificati.</p>
        <p>Ricarica la pagina per riprovare.</p>
        <button onClick={() => location.reload()}>Ricarica</button>
      </div>
    );
  }
}
