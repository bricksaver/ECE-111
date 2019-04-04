module bitcoin_hash_parallel_compute(input logic clk, reset_n, start,
								input logic [15:0] message_addr, output_addr,
								output logic done, mem_clk, mem_we,
								output logic [15:0] mem_addr,
								output logic [31:0] mem_write_data,
								input logic [31:0] mem_read_data);
								
	// SHA256 K constants
	parameter int sha256_k[0:63] = '{
		32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
		32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
		32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
		32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
		32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
		32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
		32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
		32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};
	parameter NUM_NONCES = 8'd16;
	
	// hash op function - calculates values of Wt's once each time it is called
	function logic [255:0] sha256_op(input logic [31:0] a,b,c,d,e,f,g,sum);
		logic [31:0] s0,maj,t1,t2,s1,ch;
		//creating randomness
		s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
		ch = (e & f) ^ ((~e) & g);
		t1 = ch + s1 + sum;
		s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = maj + s0;
		
		//$display("Phase_#: a-h (sha_input): %h %h %h %h %h %h %h %h", a,b,c,d,e,f,g,h);
		//$display("t1: %h, t2: %h", t1,t2);
		//$display("w: %h", w);
		//$display("k: %h", k);
		//$display("ch: %h", ch);
		//$display("s1: %h", s1);
		//$display("h: %h", h);
		//$display("Phase_#: a-h (sha_output): %h %h %h %h %h %h %h %h", t1 + t2, a, b, c, d + t1, e, f, g);
		//$display("s0: %h \n",s0);
		
		sha256_op = {t1+t2,a,b,c,d+t1,e,f,g};
	endfunction
	
	// right rotate function - right rotates values by amount specified
	
	function logic [31:0] rrot(input logic [31:0] word,
										input logic [7:0] rot_amount);
		rrot = (word>>rot_amount)|(word<<(32-rot_amount));
	endfunction
	
	logic [31:0] w[NUM_NONCES][16]; //contains previous 16 w-values
	
	// calculates newest w-value
	function logic [31:0] wtnew(input logic [7:0] k); // function with no inputs
	   logic [31:0] s0, s1;
		s0 = rrot(w[k][1],7)^rrot(w[k][1],18)^(w[k][1]>>3);
		s1 = rrot(w[k][14],17)^rrot(w[k][14],19)^(w[k][14]>>10);
		wtnew = w[k][0] + s0 + w[k][9] + s1;
	endfunction
	
	// initiate states
	enum logic [2:0] {IDLE,READ_1,READ_2,COMPUTE,WAIT,WRITE} state;
	
	// create registers to store variables
	logic [31:0] h0[NUM_NONCES],h1[NUM_NONCES],h2[NUM_NONCES],h3[NUM_NONCES],h4[NUM_NONCES],h5[NUM_NONCES],h6[NUM_NONCES],h7[NUM_NONCES];
	logic [31:0] h0_ph1,h1_ph1,h2_ph1,h3_ph1,h4_ph1,h5_ph1,h6_ph1,h7_ph1;
	logic [31:0] a[NUM_NONCES],b[NUM_NONCES],c[NUM_NONCES],d[NUM_NONCES],e[NUM_NONCES],f[NUM_NONCES],g[NUM_NONCES],h[NUM_NONCES];
	//logic [31:0] w[0:15];
	logic [31:0] sum[NUM_NONCES];
	logic [15:0] temp_read_addr, temp_write_addr, temp_read_addr_sixteen;
	logic [6:0] t, count;
	logic [1:0] phase;
	
	// assignments
	assign mem_clk = clk;
	assign done = (state === IDLE);
	
	// always_ff
	always_ff @(posedge clk, negedge reset_n) begin
		if (!reset_n) begin
			state <= IDLE;
		end
		else begin
			case (state)
				IDLE: begin
					if (start) begin
						t <= 0;
						temp_read_addr <= message_addr;
						temp_read_addr_sixteen <= message_addr + 16'd16;
						temp_write_addr <= output_addr;
						phase <= 2'd1;
						count <= 7'd0;
						state <= READ_1;
					end
				end
				READ_1: begin
					//state only called by phase 1 and 2
					if (phase === 1) begin
						//this section only run once in the very beginning
						// SHA256 Buffer Initiation - Initialize MD(Message Digest)
						h0_ph1 <= 32'h6a09e667;
						h1_ph1 <= 32'hbb67ae85;
						h2_ph1 <= 32'h3c6ef372;
						h3_ph1 <= 32'ha54ff53a;
						h4_ph1 <= 32'h510e527f;
						h5_ph1 <= 32'h9b05688c;
						h6_ph1 <= 32'h1f83d9ab;
						h7_ph1 <= 32'h5be0cd19;
						//read message word
						mem_addr <= temp_read_addr;
						mem_we <= 0;
						temp_read_addr <= temp_read_addr + 16'd1;
					end
					if (phase === 2) begin
						for (int n = 0; n < NUM_NONCES; n++) begin
							h0[n] <= h0_ph1;
							h1[n] <= h1_ph1;
							h2[n] <= h2_ph1;
							h3[n] <= h3_ph1;
							h4[n] <= h4_ph1;
							h5[n] <= h5_ph1;
							h6[n] <= h6_ph1;
							h7[n] <= h7_ph1;
						end
						//read message word
						mem_addr <= temp_read_addr_sixteen;
						mem_we <= 0;
						temp_read_addr_sixteen <= temp_read_addr_sixteen + 16'd1;
					end
					state <= READ_2;
				end
				READ_2: begin
					if (phase === 1) begin
						//this section only run once in the very beginning
						// initialize a to h
							a[0] <= h0_ph1;
							b[0] <= h1_ph1;
							c[0] <= h2_ph1;
							d[0] <= h3_ph1;
							e[0] <= h4_ph1;
							f[0] <= h5_ph1;
							g[0] <= h6_ph1;
							h[0] <= h7_ph1;
						// read message word
						mem_addr <= temp_read_addr;
						mem_we <= 0;
						temp_read_addr <= temp_read_addr + 16'd1;
					end
					if (phase === 2) begin
						for (int n = 0; n < NUM_NONCES; n++) begin
							a[n] <= h0_ph1;
							b[n] <= h1_ph1;
							c[n] <= h2_ph1;
							d[n] <= h3_ph1;
							e[n] <= h4_ph1;
							f[n] <= h5_ph1;
							g[n] <= h6_ph1;
							h[n] <= h7_ph1;
						end
						// read message word
						mem_addr <= temp_read_addr_sixteen;
						mem_we <= 0;
						temp_read_addr_sixteen <= temp_read_addr_sixteen + 16'd1;
					end
					state <= COMPUTE;
				end
				COMPUTE: begin
					case (phase)
						//phase1
						// this phase is only run once in the very beginning
						1: begin
							//compute block 1 from phase 1
								//t<=66
								if (t<67) begin
								//t<=63
								if (t<64) begin
									//t<=15 
									if (t<16) begin
										for (int n = 0; n < 15; n++) begin
											w[0][n] <= w[0][n+1];
										end
										w[0][15] <= mem_read_data;
										
										$display("current 't' value: %d", t);
										//$display("w for 0 to 15 calculated");
										
									end
									//16<=t<=63
									else begin
										for (int n = 0; n < 15; n++) begin
											w[0][n] <= w[0][n+1]; // just wires
										end
										w[0][15] <= wtnew(0);
										
										$display("current 't' value: %d", t);
										//$display("w for 16 to 63 is calculated");
										
									end
									//read another message word
									//t<=13
									if (t<14) begin
										mem_addr <= temp_read_addr;
										mem_we <= 0;
										temp_read_addr <= temp_read_addr + 16'd1;
									end
								end
								
								//***BEGIN PIPELINED CALCULATIONS***//
								//calculate hash_op - for t of previous cycle
								if (t >= 1 & t <= 64) begin
									//$display("t: %d", t-1);
									//$display("W[15]: %d",w[15]);
									if (t == 1) begin
										sum[0] <= h[0] + sha256_k[t-1] + w[0][15];
									end
									//preuse g as h
									else begin
										sum[0] <= g[0] + sha256_k[t-1] + w[0][15];
									end
								end
								if (t >= 2 & t <= 65) begin
									{a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0]} <= sha256_op(a[0],b[0],c[0],d[0],e[0],f[0],g[0],sum[0]);
								end
								//$display("Phase_1 Result - a[0]-h[0]: %h %h %h %h %h %h %h %h",a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0]);
								//***END PIPELINED CALCULATIONS***//
								
								//prep for next cycle
								t <= t + 7'd1;
								state <= COMPUTE;
							end
							//finished current block
							else begin
								t <= 0;
								phase <= 2'd2;
								//end of current block - update hash values
								h0_ph1 <= h0_ph1 + a[0];
								h1_ph1 <= h1_ph1 + b[0];
								h2_ph1 <= h2_ph1 + c[0];
								h3_ph1 <= h3_ph1 + d[0];
								h4_ph1 <= h4_ph1 + e[0];
								h5_ph1 <= h5_ph1 + f[0];
								h6_ph1 <= h6_ph1 + g[0];
								h7_ph1 <= h7_ph1 + h[0];
								//go to read_1 state
								state <= READ_1;
							end
						end
						//phase 2
						2: begin
							//compute block 2 from phase 2
							//$display("Phase_1 Result - h0_ph1-h7_ph1: %h %h %h %h %h %h %h %h", h0_ph1, h1_ph1, h2_ph1, h3_ph1, h4_ph1, h5_ph1, h6_ph1, h7_ph1);
							$display("PHASE_2 - RUNNING");
							//t<=66
							if (t<67) begin
								//t<=63
								if (t<64) begin
									//t < num_words_last_block=3 (t<=2)
									if (t<3) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											w[k][15] <= mem_read_data;
										end
									end
									//add 1 Nonce value (t=3)
									//num_words_last_block = 3
									else if (t==3) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											case (k)
												0: begin
													w[k][15] <= 32'd0;
												end
												1: begin
													w[k][15] <= 32'd1;
												end
												2: begin
													w[k][15] <= 32'd2;
												end
												3: begin
													w[k][15] <= 32'd3;
												end
												4: begin
													w[k][15] <= 32'd4;
												end
												5: begin
													w[k][15] <= 32'd5;
												end
												6: begin
													w[k][15] <= 32'd6;
												end
												7: begin
													w[k][15] <= 32'd7;
												end
												8: begin
													w[k][15] <= 32'd8;
												end
												9: begin
													w[k][15] <= 32'd9;
												end
												10: begin
													w[k][15] <= 32'd10;
												end
												11: begin
													w[k][15] <= 32'd11;
												end
												12: begin
													w[k][15] <= 32'd12;
												end
												13: begin
													w[k][15] <= 32'd13;
												end
												14: begin
													w[k][15] <= 32'd14;
												end
												15: begin
													w[k][15] <= 32'd15;
												end
											endcase
										end
									end
									//pad with a 1 (t=4)
									//num_words_last_block = 3
									else if (t==4) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											w[k][15] <= 32'h80000000;
										end
									end
									//pad with 0's till 2nd last w[t] (5<=t<=14)
									//num_words_last_block = 3
									else if (t>4 & t<=14) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											w[k][15] <= 32'h00000000;
										end
									end
									//add 64-bit representation of message length to last w[t]
									else if (t>=15 & t<16) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											//final_block_ph2 = 32'd640;
											w[k][15] <= 32'd640;
										end
										/*
										$display("current 't' value: %d", t);
										$display("w for 0 to 15 calculated");
										*/
									end
									//16<=t<=63
									else begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1]; // just wires
											end
											w[k][15] <= wtnew(k);
										end
										/*
										$display("current 't' value: %d", t);
										$display("w for 16 to 63 is calculated");
										*/
									end
									//read another message word
									//note: will possibly read empty addresses, but necessary to account
									// for 1 word final blocks
									if (t<2) begin
										mem_addr <= temp_read_addr_sixteen;
										mem_we <= 0;
										temp_read_addr_sixteen <= temp_read_addr_sixteen + 16'd1;
									end
								end
								
								//***BEGIN PIPELINED CALCULATIONS***//
								//calculate hash_op - for t of previous cycle
								if (t >= 1 & t <= 64) begin	
									//$display("t: %d", t-1);
									for (int n = 0; n < NUM_NONCES; n++) begin
										if (t == 1) begin
											sum[n] <= h[n] + sha256_k[t-1] + w[n][15];
										end
										//preuse g as h
										else begin
											sum[n] <= g[n] + sha256_k[t-1] + w[n][15];
										end
									end
								end
								if (t >= 2 & t <= 65) begin
									for (int n = 0; n < NUM_NONCES; n++) begin
										{a[n],b[n],c[n],d[n],e[n],f[n],g[n],h[n]} <= sha256_op(a[n],b[n],c[n],d[n],e[n],f[n],g[n],sum[n]);
									end
								end
								//$display("Phase_2 Result - a[0]-h[0]: %h %h %h %h %h %h %h %h",a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0]);
								//$display("Phase_2 Result - a[1]-h[1]: %h %h %h %h %h %h %h %h",a[1],b[1],c[1],d[1],e[1],f[1],g[1],h[1]);
								//$display("Phase_2 Result - a[15]-h[15]: %h %h %h %h %h %h %h %h",a[15],b[15],c[15],d[15],e[15],f[15],g[15],h[15]);
								//***END PIPELINED CALCULATIONS***//
								
								//prep for next cycle
								t <= t + 7'd1;
								state <= COMPUTE;
							end
							//finished current block
							else begin
								t <= 0;
								phase = 2'd3;
								//end of current block - update hash values
								for (int n = 0; n < NUM_NONCES; n++) begin
									h0[n] <= h0[n] + a[n];
									h1[n] <= h1[n] + b[n];
									h2[n] <= h2[n] + c[n];
									h3[n] <= h3[n] + d[n];
									h4[n] <= h4[n] + e[n];
									h5[n] <= h5[n] + f[n];
									h6[n] <= h6[n] + g[n];
									h7[n] <= h7[n] + h[n];
								end
								//done with second block - go to wait state then phase 3
								state <= WAIT;
							end
						end
						//phase3
						3: begin
							//$display("Phase_2 Result - h0[0]-h7[0]: %h %h %h %h %h %h %h %h", h0_ph2[0], h1_ph2[0], h2_ph2[0], h3_ph2[0], h4_ph2[0], h5_ph2[0], h6_ph2[0], h7_ph2[0]);
							//$display("Phase_3 - NEW Constant h0[0]-h7[0]: %h %h %h %h %h %h %h %h", h0[0], h1[0], h2[0], h3[0], h4[0], h5[0], h6[0], h7[0]);
							$display("PHASE_3 - RUNNING");	
							if (t<67) begin
								//t<=63
								if (t<64) begin
									//t<=7
									if (t<8) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											case (t)
												0: begin
													w[k][15] <= h0[k];
												end
												1: begin
													w[k][15] <= h1[k];
												end
												2: begin
													w[k][15] <= h2[k];
												end
												3: begin
													w[k][15] <= h3[k];
												end
												4: begin
													w[k][15] <= h4[k];
												end
												5: begin
													w[k][15] <= h5[k];
												end
												6: begin
													w[k][15] <= h6[k];
												end
												7: begin
													w[k][15] <= h7[k];
												end
											endcase
										end
									end
									//pad with a 1 (t=8)
									else if (t==8) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											w[k][15] <= 32'h80000000;
										end
										// SHA256 Buffer Initiation - Initialize MD(Message Digest)
										for (int n = 0; n < NUM_NONCES; n++) begin
											h0[n] <= 32'h6a09e667;
											h1[n] <= 32'hbb67ae85;
											h2[n] <= 32'h3c6ef372;
											h3[n] <= 32'ha54ff53a;
											h4[n] <= 32'h510e527f;
											h5[n] <= 32'h9b05688c;
											h6[n] <= 32'h1f83d9ab;
											h7[n] <= 32'h5be0cd19;
										end
									end
									//pad with 6 0's (9<=t<=14)
									else if (t>=9 & t<=14) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											w[k][15] <= 32'h00000000;
										end
									end
									//add 64-bit representation of message length to last w[t]
									else if (t==15) begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1];
											end
											//final_block_ph3 = 32'd256;
											w[k][15] <= 32'd256;
										end
										/*
										$display("current 't' value: %d", t);
										$display("w for 0 to 15 calculated");
										*/
									end
									//16<=t<=63
									else begin
										for (int k = 0; k < NUM_NONCES; k++) begin
											for (int n = 0; n < 15; n++) begin
												w[k][n] <= w[k][n+1]; // just wires
											end
											w[k][15] <= wtnew(k);
										end
										/*
										$display("current 't' value: %d", t);
										$display("w for 16 to 63 is calculated");
										*/
									end
								end
								
								//***BEGIN PIPELINED CALCULATIONS***//
								//calculate hash_op - for t of previous cycle
								if (t >= 1 & t <= 64) begin	
									//$display("t: %d", t-1);
									for (int n = 0; n < NUM_NONCES; n++) begin
										if (t == 1) begin
											sum[n] <= h[n] + sha256_k[t-1] + w[n][15];
										end
										//preuse g as h
										else begin
											sum[n] <= g[n] + sha256_k[t-1] + w[n][15];
										end
									end
								end
								if (t >= 2 & t <= 65) begin
									for (int n = 0; n < NUM_NONCES; n++) begin
										{a[n],b[n],c[n],d[n],e[n],f[n],g[n],h[n]} <= sha256_op(a[n],b[n],c[n],d[n],e[n],f[n],g[n],sum[n]);
									end
								end
								//$display("Phase_3 Result - a[5]-h[5]: %h %h %h %h %h %h %h %h",a[5],b[5],c[5],d[5],e[5],f[5],g[5],h[5]);
								//***END PIPELINED CALCULATIONS***//
								
								//prep for next cycle
								t <= t + 7'd1;
								state <= COMPUTE;
							end
							//finished phase 3
							else begin
								t <= 0;
								phase = 2'd1;
								//end of phase 3 - update hash values
								for (int n = 0; n < NUM_NONCES; n++) begin
									h0[n] <= h0[n] + a[n];
									h1[n] <= h1[n] + b[n];
									h2[n] <= h2[n] + c[n];
									h3[n] <= h3[n] + d[n];
									h4[n] <= h4[n] + e[n];
									h5[n] <= h5[n] + f[n];
									h6[n] <= h6[n] + g[n];
									h7[n] <= h7[n] + h[n];
								end
								//done with final block - prepare to write hash value (only h0)
								state <= WRITE;
							end
						end
					endcase
				end
				// use to assign h0_ph2 to h7_ph2
				WAIT: begin
					//state called before state 3
					//update read_addr before phase 3 of every nonce iteration
					temp_read_addr <= message_addr;
					//assign a-h to constant h0-h7 values
					for (int n = 0; n < NUM_NONCES; n++) begin
						a[n] <= 32'h6a09e667;
						b[n] <= 32'hbb67ae85;
						c[n] <= 32'h3c6ef372;
						d[n] <= 32'ha54ff53a;
						e[n] <= 32'h510e527f;
						f[n] <= 32'h9b05688c;
						g[n] <= 32'h1f83d9ab;
						h[n] <= 32'h5be0cd19;
					end
					state <= COMPUTE;
				end
				WRITE: begin
					/*
					$display("Write State - RUNNING");
					$display("nonceCount: %d", nonceCount);
					$display("Phase_3 Result - h0-h7: %h %h %h %h %h %h %h %h", h0, h1, h2, h3, h4, h5, h6, h7);
					*/
					//Run Writes one at a time since memory is single channelled
					$display("END Result - h0[0]-h0[15]: %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h",h0[0],h0[1],h0[2],h0[3],h0[4],h0[5],h0[6],h0[7],h0[8],h0[9],h0[10],h0[11],h0[12],h0[13],h0[14],h0[15]);
					mem_addr <= temp_write_addr + count;
					mem_write_data <= h0[count];
					mem_we <= 1;
					count <= count + 7'd1;
					if (count < NUM_NONCES) begin
						//temp_read_addr <= message_addr;
						//temp_read_addr_sixteen <= message_addr + 16'd16;
						state <= WRITE;
					end
					else begin
						mem_addr <= message_addr;
						temp_read_addr_sixteen <= message_addr + 16'd16;
						state <= IDLE;
					end
				end
			endcase
		end
	end
endmodule






