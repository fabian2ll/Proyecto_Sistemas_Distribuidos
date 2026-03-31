import { Module } from '@nestjs/common';
import { ElasticsearchModule } from '@nestjs/elasticsearch';
import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
  imports: [ElasticsearchModule.register({
    node: process.env.ELASTICSEARCH_NODE || 'http://localhost:9200',
  })],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
