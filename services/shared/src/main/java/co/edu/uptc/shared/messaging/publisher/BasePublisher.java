package co.edu.uptc.shared.messaging.publisher;

import java.time.Instant;
import java.util.Optional;

import org.springframework.kafka.core.KafkaTemplate;

import co.edu.uptc.shared.messaging.dto.EventDTO;
import co.edu.uptc.shared.messaging.topics.MessagingTopics;

public abstract class BasePublisher {
    private final KafkaTemplate<String, EventDTO> kafkaTemplate;

    protected BasePublisher(KafkaTemplate<String, EventDTO> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @SuppressWarnings("null")
    protected void publish(String topic, EventDTO event) {
        if (event.getTimestamp() == null) {
            event.setTimestamp(Instant.now());
        }
        String topicToSend = Optional.ofNullable(topic).orElse(MessagingTopics.AUDIT_EVENTS);
        kafkaTemplate.send(topicToSend, event);
    }
}