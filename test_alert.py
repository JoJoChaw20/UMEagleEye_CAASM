"""
Test script to trigger push notifications to Telegram.
Run this script to verify that your account receives alerts.
"""
import sys
import os

# Add the backend folder to python path so we can import app modules
sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from app.services.telegram_notifier import notify_pdpa_violation, notify_drift_event

print("🔔 Sending test PDPA violation alert...")
pdpa_success = notify_pdpa_violation(
    asset_ip="192.168.1.100",
    asset_hostname="prod-db-01",
    control_lost="Authentication disabled",
    details="Admin panel password requirement was removed."
)

print(f"PDPA Alert sent: {'✅ Success' if pdpa_success else '❌ Failed'}")

print("\n🔔 Sending test Drift event alert...")
drift_success = notify_drift_event(
    asset_ip="192.168.1.55",
    asset_hostname="web-server-main",
    event_type="configuration_change",
    severity="medium",
    changed_attribute="SSH Port",
    previous_value="22",
    new_value="2222",
    event_id="test-1234-abcd"
)

print(f"Drift Alert sent: {'✅ Success' if drift_success else '❌ Failed'}")
