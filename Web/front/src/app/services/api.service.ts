import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { map } from 'rxjs/operators';


 
@Injectable({ 
  providedIn: 'root' 
}) 
export class ApiService { 
 
 
  private REST_API_SERVER = "http://localhost:8000/"; 
  constructor(private httpClient: HttpClient) { } 
 
  getTypeRequest(url: any) { 
    return this.httpClient.get(this.REST_API_SERVER+url).pipe(map(res => { 
      return res; 
    })); 
  } 
 
  postTypeRequest(url: any, payload: any) {
    return this.httpClient.post(this.REST_API_SERVER+url, payload).pipe(map(res => { 
      return res; 
    })); 
  } 
 
  putTypeRequest(url: any, payload: any) {
    return this.httpClient.put(this.REST_API_SERVER+url, payload).pipe(map(res => { 
      return res; 
    })) 
  }
  
  checkArchives(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}archivos/`);
  }

  checkUsers(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}active_users/`);
  }
  
  checkSniffers(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}sniffer/`);
  }

  checkMail(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}mail/`);
  }

  checkMemory(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}memoria/`);
  }

  checkTmp(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}temp/`);
  }

  checkCron(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}cron/`);
  }

  checkInvalid(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}invalid/`);
  }
  checkLogs(){
    return this.httpClient.get<any>(`${this.REST_API_SERVER}logs/`);
  }

}
