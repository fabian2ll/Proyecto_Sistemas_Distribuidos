package uptc.edu.co.ms_contracts;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class MsContractsApplication {

	public static void main(String[] args) {
		SpringApplication.run(MsContractsApplication.class, args);
	}

}
