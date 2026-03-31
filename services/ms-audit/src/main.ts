import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Eureka } from 'eureka-js-client';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const port = 3000;
  await app.listen(port);

  const client = new Eureka({
    instance: {
      app: 'ms-audit',
      hostName: 'ms-audit',
      ipAddr: 'ms-audit',
      statusPageUrl: `http://ms-audit:${port}/health`,
      port: {
        '$': port,
        '@enabled': true,
      },
      vipAddress: 'ms-audit',
      dataCenterInfo: {
        '@class': 'com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo',
        name: 'MyOwn',
      },
    },
    eureka: {
      host: 'service-registry',
      port: 8761,
      servicePath: '/eureka/apps/',
    },
  });

  client.logger.level('warn');
  console.log('Iniciando proceso de registro en Eureka...');

  const connectToEureka = () => {
    client.start((error) => {
      if (error) {
        console.log('Service Registry no disponible aún. Reintentando en 15 segundos...');
        setTimeout(connectToEureka, 15000);
      } else {
        console.log('¡Registro en Eureka exitoso! ms-audit está en el ecosistema.');
      }
    });
  };

  setTimeout(connectToEureka, 15000);

  console.log(`ms-audit corriendo en el puerto ${port}`);
}
bootstrap();