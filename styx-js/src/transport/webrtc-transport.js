// styx-js/src/transport/webrtc-transport.js
// WebRTC DataChannel transport — direct browser-to-browser communication

import { TransportInterface, TransportState, TransportMessage } from './transport-interface.js';
import { EventEmitter, uuidv4 } from '../utils.js';

const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

/**
 * WebRTC DataChannel transport for direct P2P communication.
 *
 * Requires a signaling channel (provided via onSignal/sendSignal callbacks)
 * to exchange SDP offers/answers and ICE candidates during connection setup.
 * After the DataChannel is established, all data flows directly peer-to-peer.
 */
export class WebRTCTransport extends TransportInterface {
  /**
   * @param {object} options
   * @param {function(object): void} options.sendSignal - Callback to send signaling data to peer
   * @param {RTCConfiguration} [options.iceConfig] - Custom ICE configuration
   * @param {string} options.localPubkey
   * @param {string} options.peerPubkey
   */
  constructor({ sendSignal, iceConfig, localPubkey, peerPubkey }) {
    super();
    this._sendSignal = sendSignal;
    this._iceConfig = iceConfig || { iceServers: ICE_SERVERS };
    this._localPubkey = localPubkey;
    this._peerPubkey = peerPubkey;

    this._state = TransportState.DISCONNECTED;
    this._emitter = new EventEmitter();
    this._pc = null;
    this._dataChannel = null;
    this._pendingCandidates = [];
  }

  get currentState() { return this._state; }
  get isAvailable() { return typeof RTCPeerConnection !== 'undefined'; }

  onStateChange(callback) { return this._emitter.on('stateChange', callback); }
  onMessage(callback) { return this._emitter.on('message', callback); }

  /**
   * Initiate a WebRTC connection (caller/offerer role).
   */
  async connect() {
    if (!this.isAvailable) throw new Error('WebRTC not available in this environment');

    this._setState(TransportState.CONNECTING);
    this._pc = new RTCPeerConnection(this._iceConfig);
    this._setupPeerConnectionEvents();

    // Create data channel
    this._dataChannel = this._pc.createDataChannel('styx', {
      ordered: true,
      protocol: 'styx-v1',
    });
    this._setupDataChannelEvents(this._dataChannel);

    // Create and send offer
    const offer = await this._pc.createOffer();
    await this._pc.setLocalDescription(offer);
    this._sendSignal({ type: 'offer', sdp: offer.sdp });
  }

  /**
   * Process incoming signaling data from the peer.
   * Call this when you receive signaling messages.
   * @param {object} signal - { type: 'offer'|'answer'|'candidate', ... }
   */
  async handleSignal(signal) {
    if (!this._pc && signal.type === 'offer') {
      // We're the responder — create peer connection
      this._setState(TransportState.CONNECTING);
      this._pc = new RTCPeerConnection(this._iceConfig);
      this._setupPeerConnectionEvents();

      // Wait for data channel from offerer
      this._pc.ondatachannel = (event) => {
        this._dataChannel = event.channel;
        this._setupDataChannelEvents(this._dataChannel);
      };
    }

    if (!this._pc) return;

    switch (signal.type) {
      case 'offer': {
        await this._pc.setRemoteDescription(
          new RTCSessionDescription({ type: 'offer', sdp: signal.sdp })
        );
        const answer = await this._pc.createAnswer();
        await this._pc.setLocalDescription(answer);
        this._sendSignal({ type: 'answer', sdp: answer.sdp });
        this._drainPendingCandidates();
        break;
      }
      case 'answer': {
        await this._pc.setRemoteDescription(
          new RTCSessionDescription({ type: 'answer', sdp: signal.sdp })
        );
        this._drainPendingCandidates();
        break;
      }
      case 'candidate': {
        if (signal.candidate) {
          const candidate = new RTCIceCandidate(signal.candidate);
          if (this._pc.remoteDescription) {
            await this._pc.addIceCandidate(candidate);
          } else {
            this._pendingCandidates.push(candidate);
          }
        }
        break;
      }
    }
  }

  async disconnect() {
    if (this._dataChannel) {
      this._dataChannel.close();
      this._dataChannel = null;
    }
    if (this._pc) {
      this._pc.close();
      this._pc = null;
    }
    this._setState(TransportState.DISCONNECTED);
  }

  /**
   * Send a TransportMessage over the DataChannel
   */
  async send(message) {
    if (this._state !== TransportState.CONNECTED || !this._dataChannel) {
      throw new Error('WebRTC DataChannel not connected');
    }
    const json = JSON.stringify(message.toJSON());
    this._dataChannel.send(json);
  }

  // --- Private ---

  _setState(newState) {
    if (this._state !== newState) {
      this._state = newState;
      this._emitter.emit('stateChange', newState);
    }
  }

  _setupPeerConnectionEvents() {
    this._pc.onicecandidate = (event) => {
      if (event.candidate) {
        this._sendSignal({
          type: 'candidate',
          candidate: event.candidate.toJSON(),
        });
      }
    };

    this._pc.onconnectionstatechange = () => {
      switch (this._pc.connectionState) {
        case 'connected':
          // State will be set when DataChannel opens
          break;
        case 'disconnected':
        case 'failed':
        case 'closed':
          this._setState(TransportState.DISCONNECTED);
          break;
      }
    };

    this._pc.oniceconnectionstatechange = () => {
      if (this._pc.iceConnectionState === 'failed') {
        this._setState(TransportState.DISCONNECTED);
      }
    };
  }

  _setupDataChannelEvents(channel) {
    channel.onopen = () => {
      this._setState(TransportState.CONNECTED);
    };

    channel.onclose = () => {
      this._setState(TransportState.DISCONNECTED);
    };

    channel.onerror = (err) => {
      console.error('[Styx WebRTC] DataChannel error:', err);
      this._setState(TransportState.DISCONNECTED);
    };

    channel.onmessage = (event) => {
      try {
        const json = JSON.parse(event.data);
        const msg = TransportMessage.fromJSON(json);
        this._emitter.emit('message', msg);
      } catch (e) {
        console.error('[Styx WebRTC] Failed to parse message:', e);
      }
    };
  }

  async _drainPendingCandidates() {
    for (const candidate of this._pendingCandidates) {
      await this._pc.addIceCandidate(candidate);
    }
    this._pendingCandidates = [];
  }
}
