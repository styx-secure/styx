import 'package:styx_transport/src/failover/transport_failover.dart';
import 'package:styx_transport/src/tor/tor_manager.dart';
import 'package:styx_transport/src/tor/tor_transport_decorator.dart';
import 'package:styx_transport/src/transport_interface.dart';

/// Factory that creates a [TransportFailover] chain based on user preferences.
class TransportSelector {
  /// Creates a failover chain.
  ///
  /// Default hierarchy:
  /// 1. Nostr (3 retries, 5s timeout)
  /// 2. Email (2 retries, 30s timeout) — if provided
  ///
  /// If [useTor] is true and [torManager] is provided, transports
  /// are wrapped with [TorTransportDecorator].
  TransportFailover createFailoverChain({
    required TransportInterface nostr,
    TransportInterface? email,
    TorManager? torManager,
    bool useTor = false,
  }) {
    var effectiveNostr = nostr;
    var effectiveEmail = email;

    if (useTor && torManager != null) {
      effectiveNostr = TorTransportDecorator(
        inner: nostr,
        torManager: torManager,
      );
      if (email != null) {
        effectiveEmail = TorTransportDecorator(
          inner: email,
          torManager: torManager,
        );
      }
    }

    final transports = <TransportPriority>[
      TransportPriority(
        transport: effectiveNostr,
        maxRetries: 3,
        timeout: const Duration(seconds: 5),
      ),
      if (effectiveEmail != null)
        TransportPriority(
          transport: effectiveEmail,
          maxRetries: 2,
          timeout: const Duration(seconds: 30),
        ),
    ];

    return TransportFailover(transports: transports);
  }
}
