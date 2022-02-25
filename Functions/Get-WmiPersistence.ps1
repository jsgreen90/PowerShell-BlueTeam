function Get-WmiPersistence {
    Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription
    Get-WmiObject -Class __EventFilter -Namespace root\subscription
    Get-WmiObject -Class __EventConsumer -Namespace root\subscription
}
