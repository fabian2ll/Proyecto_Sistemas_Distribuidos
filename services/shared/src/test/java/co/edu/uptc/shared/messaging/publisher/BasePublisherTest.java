package co.edu.uptc.shared.messaging.publisher;

import co.edu.uptc.shared.messaging.dto.EventDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class BasePublisherTest {

    @Mock
    private KafkaTemplate<String, EventDTO> kafkaTemplate;

    private TestPublisher publisher;

    private static class TestPublisher extends BasePublisher {
        public TestPublisher(KafkaTemplate<String, EventDTO> kafkaTemplate) {
            super(kafkaTemplate);
        }

        public void publishEvent(String topic, EventDTO event) {
            super.publish(topic, event);
        }
    }

    @BeforeEach
    void setUp() {
        publisher = new TestPublisher(kafkaTemplate);
    }

    @Test
    @SuppressWarnings("null")
    void testPublishSetsTimestampIfNull() {
        EventDTO event = new EventDTO(null, "test-service", "TEST_ACTION", "data");

        publisher.publishEvent("test-topic", event);

        ArgumentCaptor<EventDTO> eventCaptor = ArgumentCaptor.forClass(EventDTO.class);
        verify(kafkaTemplate).send(eq("test-topic"), eventCaptor.capture());

        EventDTO capturedEvent = eventCaptor.getValue();
        assertNotNull(capturedEvent.getTimestamp());
        assertEquals("test-service", capturedEvent.getServiceOrigin());
    }

    @Test
    @SuppressWarnings("null")
    void testPublishKeepsExistingTimestamp() {
        Instant past = Instant.parse("2020-01-01T00:00:00Z");
        EventDTO event = new EventDTO(past, "test-service", "TEST_ACTION", "data");

        publisher.publishEvent("test-topic", event);

        ArgumentCaptor<EventDTO> eventCaptor = ArgumentCaptor.forClass(EventDTO.class);
        verify(kafkaTemplate).send(eq("test-topic"), eventCaptor.capture());

        EventDTO capturedEvent = eventCaptor.getValue();
        assertEquals(past, capturedEvent.getTimestamp());
    }
}
