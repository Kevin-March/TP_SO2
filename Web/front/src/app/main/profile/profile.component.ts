import { Component, OnInit } from '@angular/core'; 
import { Router } from '@angular/router'; 
import { AuthService } from 'src/app/services/auth.service'; 
import {ApiService} from '../../services/api.service' 
 
@Component({ 
  selector: 'app-profile', 
  templateUrl: './profile.component.html', 
  styleUrls: ['./profile.component.scss'] 
}) 
export class ProfileComponent implements OnInit { 
 
  constructor( 
    private _api : ApiService, 
    private _auth: AuthService, 
  ) { } 
 
  ngOnInit(): void { 
    this.test_jwt() 
  } 
 
  test_jwt(){ 
    this._api.getTypeRequest('test-jwt').subscribe((res: any) => { 
      console.log(res) 
 
    }, err => { 
      console.log(err) 
    }); 
  } 

  Archives(): void{
    console.log('Archives');
    this._api.checkArchives().subscribe(resp => {
      console.log(resp)
    });
  }
  Users(): void{
    console.log('Users');
    this._api.checkUsers().subscribe(resp => {
      console.log(resp)
    })
  }
  Sniffers(): void{
    console.log('Sniffers')
    this._api.checkSniffers().subscribe(resp => {
      console.log(resp)
    })
  }
  Logs(): void{
    console.log('Logs')
    this._api.checkLogs().subscribe(resp => {
      console.log(resp)
    })
  }
  Mails(): void{
    console.log('Mail')
    this._api.checkMail().subscribe(resp => {
      console.log(resp)
    })
  }
  Memory(): void{
    console.log('Memory')
    this._api.checkMemory().subscribe(resp => {
      console.log(resp)
    })
  }
  Temp(): void{
    console.log('Temp')
    this._api.checkTmp().subscribe(resp => {
      console.log(resp)
    })
  }
  DDOS(): void{
    console.log('hola')
  }
  CRON(): void{
    console.log("Cron")
    this._api.checkCron().subscribe(resp => {
      console.log(resp)
    })
  }
  Invalid(): void{
    console.log('Invalid')
    this._api.checkInvalid().subscribe(resp => {
      console.log(resp)
    })
  }

}
