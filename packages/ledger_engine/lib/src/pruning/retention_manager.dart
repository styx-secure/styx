import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';

/// Manages retention policies and automatic pruning.
class RetentionManager {
  /// Returns events that have exceeded the [retentionPeriod].
  ///
  /// Only events of [applicableTypes] are considered.
  /// Already-pruned events are excluded.
  List<LedgerEvent> getExpiredEvents({
    required List<LedgerEvent> events,
    required Duration retentionPeriod,
    required List<EventType> applicableTypes,
  }) {
    final cutoff = DateTime.now().subtract(retentionPeriod);
    return events
        .where(
          (e) =>
              !e.isPruned &&
              applicableTypes.contains(e.eventType) &&
              e.createdAt.isBefore(cutoff),
        )
        .toList();
  }
}
