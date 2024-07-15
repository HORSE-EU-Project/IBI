import intent_manager

def execute_alert_box(alert):
    print('alert box ready - waiting for security alerts')
    class Converted_intent:
        intent_type = ''
        threat = ''
        host = []
        duration = 0
    new_intent = Converted_intent()

    new_intent.intent_type = alert.alert_type
    new_intent.threat = alert.threat
    new_intent.host = alert.host
    new_intent.duration = str(alert.duration)

    intent_manager.execute_intent_manager(new_intent)

