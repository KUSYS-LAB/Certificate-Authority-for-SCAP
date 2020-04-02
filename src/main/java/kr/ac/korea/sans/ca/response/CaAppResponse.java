package kr.ac.korea.sans.ca.response;

import org.springframework.lang.NonNull;

public class CaAppResponse <T> {

	@NonNull
	private T data;
	
	public CaAppResponse () {
		
	}
	
	public CaAppResponse(T data) {
		this.data = data;
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}

	@Override
	public String toString() {
		return "CaAppResponse [data=" + data + "]";
	}
	
	
}
